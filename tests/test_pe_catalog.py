# SPDX-License-Identifier: Apache-2.0
"""Tests for catalog signing (W2.3): ``.cat`` parsing, the hash → catalog
index and the three-state ``catalog_lookup``.

Real-artifact assertions (ground rules 22/29) run against the tier-5
CatRoot copy in the corpus and are skipped where it is absent — Microsoft's
own catalogs are tier-5 artifacts, so they stay on the corpus machines and
are never committed here. The corpus carries the CatRoot from the same
install as the tier-5 System32 slice; between them they cover four slice
files that carry no embedded signature
(``AssignedAccessCsp.dll``, ``AssignedAccessManager.dll``,
``assignedaccessmanagersvc.dll``, ``dumpsdport.sys``), whose authentihash
blint computes and matches against the member hash Windows' own signing
tooling stored in the catalog.
Layout variants: real Windows 11 package catalogs use a simplified CTL
(entries in a plain SEQUENCE, every member as a SHA-1 + SHA-256 entry
pair); the classic RFC 5283-style CTL (version INTEGER first, entries
under [1] IMPLICIT with CatalogNameValue/MemberInfo attributes naming
members) is covered by a hand-built DER fixture in that shape. Hostile
and cap fixtures exceed the caps they test (ground rule 33): a catalog
past the *default* member cap, a file past the default size cap,
truncated CTLs, cyclic trees — every refusal must degrade to a recorded
degradation that marks the index incomplete, never raise, and never let a
negative lookup manufacture an "unsigned" verdict.
"""

import os

import pytest

from blint.lib.checks import (
    check_authenticode,
    check_signature_not_timestamped,
    check_weak_signature_digest,
)
from blint.lib.pe_catalog import (
    MAX_CATALOG_MEMBERS,
    CatalogLimits,
    apply_catalog_signature,
    build_catalog_index,
    lookup_member,
    parse_catalog_file,
)
from tests.test_pe_signature import _cert_tlv, _oid, _signer_info, _tlv

SLICE_ROOT = os.path.expanduser("~/sandbox/pe-corpus/tier5-system")
CATROOT = os.path.join(SLICE_ROOT, "catroot")

SHA1_HASH = "a" * 40
SHA1_HASH2 = "b" * 40
SHA256_HASH = "c" * 64


# ---------------------------------------------------------------------------
# DER builders (sharing the tested pe_signature fixture builders).
# ---------------------------------------------------------------------------
def _bmp(text: str) -> bytes:
    return _tlv(0x1E, text.encode("utf-16-be"))


def _utf16(text: str) -> bytes:
    return _tlv(0x04, text.encode("utf-16-le") + b"\x00\x00")


def _catalog_name_value_hash() -> bytes:
    """The attribute real Windows 11 package catalogs carry on every member
    entry: OID 1.3.6.1.4.1.311.12.2.3 with an empty SpcLink."""
    return _tlv(
        0x30,
        _oid("1.3.6.1.4.1.311.12.2.3") + _tlv(0x31, _tlv(0xA2, _tlv(0xA0, b""))),
    )


def _member_indirect_data(hash_bytes: bytes) -> bytes:
    """SpcIndirectData attribute carrying the member digest (the SHA-256
    entry of each real member pair carries this)."""
    inner = _tlv(
        0x30,
        _tlv(0x30, _oid("1.3.6.1.4.1.311.2.1.25") + _tlv(0xA2, _tlv(0xA0, b"")))
        + _tlv(
            0x30,
            _tlv(0x30, _oid("2.16.840.1.101.3.4.2.1") + _tlv(0x05, b""))
            + _tlv(0x04, hash_bytes),
        ),
    )
    return _tlv(0x30, _oid("1.3.6.1.4.1.311.2.1.4") + _tlv(0x31, inner))


def _modern_member_entry(hash_hex: str, with_digest: bool = False) -> bytes:
    hash_bytes = bytes.fromhex(hash_hex)
    attrs = [_catalog_name_value_hash()]
    if with_digest:
        attrs.append(_member_indirect_data(hash_bytes))
    return _tlv(0x30, _tlv(0x04, hash_bytes) + _tlv(0x31, b"".join(attrs)))


def _classic_member_entry(hash_hex: str, name: str, indirect_cat: str) -> bytes:
    """Classic makecat-era entry: CatalogNameValue names the member file,
    MemberInfo names the indirect catalog — both via SpcLink strings."""
    name_value = _tlv(
        0x30,
        _oid("1.3.6.1.4.1.311.12.1.1")
        + _tlv(
            0x31,
            _tlv(
                0x30,
                _oid("1.3.6.1.4.1.311.12.2.2") + _tlv(0xA0, _tlv(0xA0, _bmp(name))),
            ),
        ),
    )
    member_info = _tlv(
        0x30,
        _oid("1.3.6.1.4.1.311.12.1.2")
        + _tlv(
            0x31,
            _tlv(
                0x30,
                _oid("1.3.6.1.4.1.311.12.1.1") + _tlv(0xA2, _tlv(0xA0, _bmp(indirect_cat))),
            ),
        ),
    )
    return _tlv(
        0x30,
        _tlv(0x04, bytes.fromhex(hash_hex)) + _tlv(0x31, name_value + member_info),
    )


def _modern_ctl(entries: list[bytes], list_id: bytes = b"\x11" * 16) -> bytes:
    """The simplified CTL real Windows 11 package catalogs use: no version
    INTEGER, attribute markers as leading SEQUENCEs, entries in a plain
    SEQUENCE, OS attributes under [0]."""
    return _tlv(
        0x30,
        _tlv(0x30, _oid("1.3.6.1.4.1.311.12.1.1"))
        + _tlv(0x04, list_id)
        + _tlv(0x17, b"240401075722Z")
        + _tlv(0x30, _oid("1.3.6.1.4.1.311.12.1.3") + _tlv(0x05, b""))
        + _tlv(0x30, b"".join(entries))
        + _tlv(
            0xA0,
            _tlv(0x30, _tlv(0x30, _oid("1.3.6.1.4.1.311.12.2.1") + _utf16("OSAttr:2:10.0"))),
        ),
    )


def _classic_ctl(entries: list[bytes]) -> bytes:
    """The classic RFC 5283-style CTL: version INTEGER, subject usage,
    list identifier, sequence number, thisUpdate, entries under [1]."""
    return _tlv(
        0x30,
        _tlv(0x02, b"\x01")
        + _tlv(0x30, _oid("1.3.6.1.4.1.311.10.3.1"))
        + _tlv(0x04, b"")
        + _tlv(0x04, b"\x01")
        + _tlv(0x17, b"240101000000Z")
        + _tlv(0xA1, b"".join(entries)),
    )


def _cat_content_info(
    ctl: bytes, signer_cn: str = "Leaf", serial: int = 1, digest_oid: str = "2.16.840.1.101.3.4.2.1"
) -> bytes:
    """A PKCS#7 ContentInfo wrapping SignedData whose encapsulated content
    is the CTL — the .cat file shape. ``ctl`` arrives as a complete TLV
    (from ``_modern_ctl``/``_classic_ctl``), which is what the eContent
    [0] holds."""
    signed_data = (
        _tlv(0x02, b"\x01")
        + _tlv(0x31, _tlv(0x30, _oid("2.16.840.1.101.3.4.2.1")))
        + _tlv(0x30, _oid("1.3.6.1.4.1.311.10.1") + _tlv(0xA0, ctl))
        + _tlv(0xA0, _cert_tlv(serial, signer_cn, signer_cn))
        + _tlv(0x31, _signer_info(serial, signer_cn, digest_oid))
    )
    return _tlv(0x30, _oid("1.2.840.113549.1.7.2") + _tlv(0xA0, _tlv(0x30, signed_data)))


def _write_cat(tmp_path, name: str, blob: bytes) -> str:
    path = os.path.join(str(tmp_path), name)
    with open(path, "wb") as handle:
        handle.write(blob)
    return path


def _member_metadata(sha1_hex: str, sha256_hex: str) -> dict:
    """A minimal parsed-PE metadata shape apply_catalog_signature reads."""
    return {
        "binary_type": "PE",
        "name": "member.dll",
        "authenticode": {"sha1_hash": ":".join(sha1_hex[i : i + 2] for i in range(0, 80, 2)),
                         "sha256_hash": ":".join(sha256_hex[i : i + 2] for i in range(0, 128, 2))},
        "code_signature": {
            "parse_status": "absent",
            "scope": "none",
            "catalog_lookup": "not_performed",
            "signatures": [],
            "signature_count": 0,
        },
        "security_properties": {},
        "security_properties_gaps": ["authenticode_scope", "signed_page_hashes"],
    }


# ---------------------------------------------------------------------------
# Real artifacts (rules 22/29): the corpus CatRoot, never committed here.
# ---------------------------------------------------------------------------
def _corpus_catalogs() -> list[str]:
    if not os.path.isdir(CATROOT):
        pytest.skip("tier-5 CatRoot not present")
    return sorted(
        os.path.join(CATROOT, name)
        for name in os.listdir(CATROOT)
        if name.endswith(".cat")
    )


def test_real_catalog_parse_and_index():
    catalogs = _corpus_catalogs()
    assert len(catalogs) >= 2
    for path in catalogs:
        catalog = parse_catalog_file(path)
        assert catalog["parse_status"] == "parsed", (path, catalog["parse_error"])
        assert catalog["member_count"] > 0
        # Real package catalogs: a Microsoft signer with a timestamp, and
        # both hash widths for every member.
        signer = catalog["signatures"][0]["signer"]
        assert signer["cn"] in ("Microsoft Windows", "Microsoft Windows Publisher"), path
        assert catalog["signatures"][0]["timestamp"]["present"] is True
        assert catalog["signatures"][0]["timestamp"]["kind"] == "rfc3161"
        assert catalog["attribute_counts"].get("catalogNameValueHash", 0) > 0
        algorithms = {algorithm for _, algorithm in catalog["hashes"]}
        assert algorithms == {"SHA1", "SHA256"}, path
        assert catalog["member_count"] == catalog["member_hashes_stored"]

    index = build_catalog_index(CATROOT)
    assert index["catalog_count"] == len(catalogs)
    assert index["complete"] is True
    assert index["degradation_count"] == 0
    assert index["indexed_entry_count"] > 0
    assert index["entry_count"] >= index["indexed_entry_count"]
    # A member of a committed catalog is findable by its exact hash.
    first_catalog = parse_catalog_file(catalogs[0])
    first_hash = first_catalog["hashes"][0][0]
    hit = lookup_member(
        index,
        first_hash if len(first_hash) == 64 else None,
        first_hash if len(first_hash) == 40 else None,
    )
    assert hit and hit["catalog"] == catalogs[0]


def test_real_slice_driver_resolves_through_corpus_catalog():
    """The packet's rule-29 assertion: blint computes a slice file's
    authentihash, finds no embedded blob (scope "none"), and matches it as
    a member hash Windows' own tooling stored in the real corpus
    CatRoot catalog — the same match ``Get-AuthenticodeSignature`` reports as
    SignatureType "Catalog"."""
    if not os.path.isdir(SLICE_ROOT) or not os.path.isdir(CATROOT):
        pytest.skip("tier-5 slice not present")
    from blint.lib.binary import parse

    index = build_catalog_index(CATROOT)
    members = [
        ("system32/AssignedAccessCsp.dll", os.path.join(SLICE_ROOT, "system32/AssignedAccessCsp.dll")),
        ("system32/AssignedAccessManager.dll", os.path.join(SLICE_ROOT, "system32/AssignedAccessManager.dll")),
        ("system32/assignedaccessmanagersvc.dll", os.path.join(SLICE_ROOT, "system32/assignedaccessmanagersvc.dll")),
        ("drivers/dumpsdport.sys", os.path.join(SLICE_ROOT, "drivers/dumpsdport.sys")),
    ]
    for label, path in members:
        if not os.path.exists(path):
            pytest.skip(f"{label} not in the local slice")
        metadata = parse(path)
        assert metadata["code_signature"]["scope"] == "none", label
        apply_catalog_signature(metadata, index)
        block = metadata["code_signature"]
        assert block["scope"] == "catalog", (label, block["catalog_lookup"])
        assert block["catalog_lookup"] == "positive"
        assert block["parse_status"] == "parsed"
        assert block["catalog"]["member_hash_algorithm"] in ("SHA1", "SHA256")
        assert block["catalog"]["catalog"].endswith(".cat")
        assert block["signatures"][0]["signer"]["cn"] in (
            "Microsoft Windows",
            "Microsoft Windows Publisher",
        )
        assert block["structural_integrity"]["digest_match"] is True
        assert metadata["security_properties"]["authenticode_scope"] == "catalog"
        assert check_authenticode(path, metadata, {}) is True


# ---------------------------------------------------------------------------
# Layout variants (ground rule 10).
# ---------------------------------------------------------------------------
def test_modern_layout_members_signer_and_counts(tmp_path):
    blob = _cat_content_info(
        _modern_ctl(
            [
                _modern_member_entry(SHA256_HASH, with_digest=True),
                _modern_member_entry(SHA1_HASH),
            ]
        ),
        signer_cn="Cat Signer",
    )
    path = _write_cat(tmp_path, "modern.cat", blob)
    catalog = parse_catalog_file(path)
    assert catalog["parse_status"] == "parsed", catalog["parse_error"]
    assert catalog["member_count"] == 2
    assert catalog["member_hashes_stored"] == 2
    assert catalog["attribute_counts"]["catalogNameValueHash"] == 2
    assert catalog["attribute_counts"]["spcIndirectData"] == 1
    assert catalog["list_identifier_hex"] == "11" * 16
    assert catalog["this_update"] == "2024-04-01T07:57:22Z"
    # The simplified layout has no version INTEGER, so no usage OID is
    # claimed from its leading attribute markers.
    assert "subject_usage_oid" not in catalog
    signer = catalog["signatures"][0]["signer"]
    assert signer["cn"] == "Cat Signer"
    # The minimal fixture certificate carries no EKU extension.
    assert signer["eku"] == []
    index = build_catalog_index(str(tmp_path))
    assert index["complete"] is True
    assert index["entry_count"] == 2
    assert index["indexed_entry_count"] == 2
    assert lookup_member(index, SHA256_HASH, None)["member_hash_algorithm"] == "SHA256"
    assert lookup_member(index, None, SHA1_HASH)["member_hash_algorithm"] == "SHA1"


def test_classic_layout_names_and_indirect_members(tmp_path):
    blob = _cat_content_info(
        _classic_ctl(
            [
                _classic_member_entry(SHA1_HASH, "member.dll", "indirect.cat"),
                _classic_member_entry(SHA1_HASH2, "other.dll", "indirect.cat"),
            ]
        )
    )
    path = _write_cat(tmp_path, "classic.cat", blob)
    catalog = parse_catalog_file(path)
    assert catalog["parse_status"] == "parsed", catalog["parse_error"]
    assert catalog["member_count"] == 2
    assert catalog["member_named_count"] == 2
    assert catalog["indirect_member_count"] == 2
    assert "member.dll" in catalog["member_names"]
    assert "other.dll" in catalog["member_names"]
    # The classic layout's leading INTEGER marks the usage OID as real.
    assert catalog["subject_usage_oid"] == "1.3.6.1.4.1.311.10.3.1"
    assert catalog["this_update"] == "2024-01-01T00:00:00Z"
    index = build_catalog_index(str(tmp_path))
    assert lookup_member(index, None, SHA1_HASH2) is not None


def test_catalog_without_signer_still_indexes(tmp_path):
    ctl = _modern_ctl([_modern_member_entry(SHA256_HASH)])
    signed_data = (
        _tlv(0x02, b"\x01")
        + _tlv(0x31, _tlv(0x30, _oid("2.16.840.1.101.3.4.2.1")))
        + _tlv(0x30, _oid("1.3.6.1.4.1.311.10.1") + _tlv(0xA0, ctl))
        # No certificates, no signerInfos.
    )
    blob = _tlv(0x30, _oid("1.2.840.113549.1.7.2") + _tlv(0xA0, _tlv(0x30, signed_data)))
    path = _write_cat(tmp_path, "unsigned.cat", blob)
    catalog = parse_catalog_file(path)
    # The members are still the OS's own: parsed, with the signer gap named.
    assert catalog["parse_status"] == "parsed", catalog["parse_error"]
    assert catalog["signer_unreadable"] is True
    assert catalog["signatures"] == []
    index = build_catalog_index(str(tmp_path))
    assert lookup_member(index, SHA256_HASH, None) is not None


def test_not_a_catalog_content_type_refused(tmp_path):
    ctl = _tlv(
        0x30,
        _tlv(0x30, _oid("1.3.6.1.4.1.311.12.1.1"))
        + _tlv(0x04, b"\x11" * 16)
        + _tlv(0x17, b"240401075722Z")
        + _tlv(0x30, b"")
        + _tlv(0x30, _modern_member_entry(SHA256_HASH)),
    )
    signed_data = (
        _tlv(0x02, b"\x01")
        + _tlv(0x31, _tlv(0x30, _oid("2.16.840.1.101.3.4.2.1")))
        + _tlv(0x30, _oid("1.3.6.1.4.1.311.2.1.4") + _tlv(0xA0, ctl))
        + _tlv(0xA0, _cert_tlv(1, "Leaf", "Leaf"))
        + _tlv(0x31, _signer_info(1, "Leaf", "2.16.840.1.101.3.4.2.1"))
    )
    blob = _tlv(0x30, _oid("1.2.840.113549.1.7.2") + _tlv(0xA0, _tlv(0x30, signed_data)))
    _write_cat(tmp_path, "notacat.cat", blob)
    index = build_catalog_index(str(tmp_path))
    assert index["catalog_count"] == 1
    assert index["complete"] is False
    assert index["degradations"][0]["reason"].startswith("not_a_catalog")


# ---------------------------------------------------------------------------
# Hostile input (ground rule 30): degrade, record, never raise.
# ---------------------------------------------------------------------------
def test_hostile_truncated_ctl_keeps_real_hashes_and_marks_incomplete(tmp_path):
    """A hostile CTL whose last TLV declares more bytes than the file has:
    the catalog is malformed, its counts are floors, and the entries read
    before the lie are still real hashes — but the index can never decide
    "negative" from what it kept."""
    ctl = _modern_ctl(
        [_modern_member_entry(SHA1_HASH), _modern_member_entry(SHA256_HASH)]
    )
    # Inflate the trailing OS-attribute [0] TLV's short-form length: the
    # entries container itself stays readable, so the entries before the
    # lie are salvaged while the CTL walk records the truncation.
    marker = _oid("1.3.6.1.4.1.311.12.2.1")
    lie_at = ctl.index(marker) - 6  # [0] header | SEQ | SEQ | OID TLV
    assert ctl[lie_at] == 0xA0
    ctl = ctl[:lie_at] + bytes([0xA0, ctl[lie_at + 1] + 0x40]) + ctl[lie_at + 2 :]
    path = _write_cat(tmp_path, "truncated.cat", _cat_content_info(ctl))
    catalog = parse_catalog_file(path)
    assert catalog["parse_status"] == "malformed"
    assert catalog["parse_error"] == "ctl_entries_truncated"
    assert catalog["members_truncated"] is True
    assert catalog["member_count"] == 2
    assert catalog["member_hashes_stored"] == 2
    index = build_catalog_index(str(tmp_path))
    assert index["complete"] is False
    assert index["catalogs_refused"] == 1
    # The entries read before the lie were real and stay findable...
    assert lookup_member(index, SHA256_HASH, None) is not None
    # ...but a hash the index never saw is "index_incomplete", not negative.
    metadata = _member_metadata("e" * 40, "f" * 64)
    apply_catalog_signature(metadata, index)
    assert metadata["code_signature"]["catalog_lookup"] == "index_incomplete"


def test_incomplete_index_still_answers_the_members_it_did_index(tmp_path):
    """An incomplete index still resolves a positive match.

    Only the negative needs the whole index: finding the member is proof, and
    a hash the index *did* store is proof whether or not some other catalog
    in the tree was refused. Deciding ``index_incomplete`` before looking
    turned one corrupt .cat anywhere in a CatRoot tree into "unknown" for
    every catalog-signed file in the scan — the feature switching itself off
    on the first bad file, which is the one outcome W2.3 exists to prevent.
    """
    ctl = _modern_ctl([_modern_member_entry(SHA1_HASH), _modern_member_entry(SHA256_HASH)])
    _write_cat(tmp_path, "good.cat", _cat_content_info(ctl))
    # A second catalog the index must refuse, so the tree is incomplete.
    _write_cat(tmp_path, "broken.cat", b"\x30\x80not-a-catalog")
    index = build_catalog_index(str(tmp_path))
    assert index["complete"] is False
    assert index["catalogs_refused"] == 1
    metadata = _member_metadata(SHA1_HASH, SHA256_HASH)
    apply_catalog_signature(metadata, index)
    block = metadata["code_signature"]
    assert block["scope"] == "catalog"
    assert block["catalog_lookup"] == "positive"
    assert block["catalog"]["member_hash_algorithm"] == "SHA256"
    # The match stands and the reader is told what it stands on.
    assert block["catalog_index_incomplete"] is True
    assert check_authenticode("member.dll", metadata, {}) is True


def test_hostile_oversized_file_past_the_default_cap(tmp_path):
    path = os.path.join(str(tmp_path), "big.cat")
    with open(path, "wb") as handle:
        handle.seek(32 * 1024 * 1024)
        handle.write(b"\x00")
    catalog = parse_catalog_file(path)
    assert catalog["parse_status"] == "malformed"
    assert catalog["parse_error"].startswith("file_too_large")
    index = build_catalog_index(str(tmp_path))
    assert index["complete"] is False
    assert index["catalogs_refused"] == 1
    assert index["entry_count"] == 0


def test_member_cap_exceeded_reports_incomplete_not_negative(tmp_path):
    """The packet's subject: a hash the catalog carries but the capped index
    does not store must never read as "not signed"."""
    entries = [_modern_member_entry(f"{index:064x}") for index in range(7)]
    _write_cat(tmp_path, "cap.cat", _cat_content_info(_modern_ctl(entries)))
    limits = CatalogLimits(max_catalog_members=5)
    index = build_catalog_index(str(tmp_path), limits)
    catalog = parse_catalog_file(
        os.path.join(str(tmp_path), "cap.cat"), limits
    )
    assert catalog["member_count"] == 7, "the count stays exact past the cap"
    assert catalog["member_hashes_stored"] == 5
    assert catalog["members_stored_capped"] is True
    assert index["complete"] is False
    assert index["entry_count"] == 7
    metadata = _member_metadata(f"{6:040x}", f"{6:064x}")  # in the catalog, past the stored cap
    apply_catalog_signature(metadata, index)
    assert metadata["code_signature"]["catalog_lookup"] == "index_incomplete"
    assert check_authenticode("member.dll", metadata, {}) is True, (
        "an incomplete index cannot decide 'unsigned'"
    )


def test_default_member_cap_exceeded_exact_count(tmp_path):
    """Ground rule 33 against the shipped constant: one entry past the
    default window, and the count beside the capped store stays exact."""
    count = MAX_CATALOG_MEMBERS + 1
    entries = [_modern_member_entry(f"{index:064x}") for index in range(count)]
    catalog = parse_catalog_file(
        _write_cat(tmp_path, "wide.cat", _cat_content_info(_modern_ctl(entries)))
    )
    assert catalog["member_count"] == count
    assert catalog["member_hashes_stored"] == MAX_CATALOG_MEMBERS
    assert catalog["members_stored_capped"] is True


def test_catalog_and_entry_caps(tmp_path):
    for number in range(3):
        entries = [
            _modern_member_entry(f"{number:02x}{index:062x}") for index in range(2)
        ]
        _write_cat(tmp_path, f"cat{number}.cat", _cat_content_info(_modern_ctl(entries)))
    limits = CatalogLimits(
        max_catalogs_indexed=2,
        max_index_entries=3,
    )
    index = build_catalog_index(str(tmp_path), limits)
    assert index["catalog_count"] == 3, "the walk always finishes: the count is exact"
    assert index["entry_count"] == 6
    assert index["catalogs_indexed"] == 2
    assert index["indexed_entry_count"] == 3
    assert index["complete"] is False
    reasons = [d["reason"] for d in index["degradations"]]
    assert "catalog_cap_exceeded" in reasons
    assert "index_entry_cap_exceeded" in reasons


def test_walk_cap_and_cyclic_symlinks(tmp_path):
    _write_cat(tmp_path, "a.cat", _cat_content_info(_modern_ctl([_modern_member_entry(SHA1_HASH)])))
    os.symlink(str(tmp_path), os.path.join(str(tmp_path), "loop"))
    # A cyclic tree cannot loop the walk (directory symlinks are not
    # followed) and the default limits index it completely.
    index = build_catalog_index(str(tmp_path))
    assert index["catalog_count"] == 1
    assert index["complete"] is True
    assert lookup_member(index, None, SHA1_HASH) is not None

    # A walk cap makes the walked counts floors and marks the index.
    tiny = CatalogLimits(max_walked_files=1)
    small_dir = tmp_path / "small"
    small_dir.mkdir()
    _write_cat(small_dir, "b.cat", _cat_content_info(_modern_ctl([_modern_member_entry(SHA256_HASH)])))
    _write_cat(small_dir, "c.txt", b"not a catalog")
    index = build_catalog_index(str(small_dir), tiny)
    assert index["files_walked_truncated"] is True
    assert index["complete"] is False


def test_empty_directory_is_incomplete(tmp_path):
    """Ground rule 32, the empty case: a directory with no catalogs cannot
    answer "negative" — a wrong --catalog-dir must not sign off a tree."""
    index = build_catalog_index(str(tmp_path))
    assert index["catalog_count"] == 0
    assert index["complete"] is False
    assert index["degradations"][0]["reason"] == "no_catalog_files"
    metadata = _member_metadata(SHA1_HASH, SHA256_HASH)
    apply_catalog_signature(metadata, index)
    assert metadata["code_signature"]["catalog_lookup"] == "index_incomplete"


# ---------------------------------------------------------------------------
# The three states and the rule (rules 11, 14, 32).
# ---------------------------------------------------------------------------
def test_lookup_prefers_sha256_and_falls_back_to_sha1():
    index = {
        "entries": {
            SHA256_HASH: {"catalog": "a.cat", "algorithm": "SHA256"},
            SHA1_HASH: {"catalog": "b.cat", "algorithm": "SHA1"},
        }
    }
    hit = lookup_member(index, SHA256_HASH, SHA1_HASH)
    assert hit["member_hash_algorithm"] == "SHA256"
    del index["entries"][SHA256_HASH]
    assert lookup_member(index, SHA256_HASH, SHA1_HASH)["member_hash_algorithm"] == "SHA1"
    assert lookup_member(index, SHA256_HASH, "d" * 40) is None
    assert lookup_member(None, SHA256_HASH, SHA1_HASH) is None


def test_apply_without_index_is_a_no_op():
    metadata = _member_metadata(SHA1_HASH, SHA256_HASH)
    apply_catalog_signature(metadata, None)
    block = metadata["code_signature"]
    assert block["scope"] == "none"
    assert block["catalog_lookup"] == "not_performed"
    assert check_authenticode("member.dll", metadata, {}) is True


def test_apply_positive_match_reads_one_block_for_both_scopes(tmp_path):
    _write_cat(
        tmp_path,
        "hit.cat",
        _cat_content_info(_modern_ctl([_modern_member_entry(SHA256_HASH, with_digest=True)]),
                          signer_cn="Cat Signer"),
    )
    index = build_catalog_index(str(tmp_path))
    metadata = _member_metadata(SHA1_HASH, SHA256_HASH)
    apply_catalog_signature(metadata, index)
    block = metadata["code_signature"]
    assert block["scope"] == "catalog"
    assert block["catalog_lookup"] == "positive"
    assert block["catalog"]["catalog"].endswith("hit.cat")
    assert block["catalog"]["member_hash"] == SHA256_HASH
    assert block["catalog"]["member_hash_algorithm"] == "SHA256"
    assert block["parse_status"] == "parsed"
    assert block["signatures"][0]["signer"]["cn"] == "Cat Signer"
    assert block["signature_count"] == 1
    assert block["weak_digest_only"] is False
    assert block["structural_integrity"]["digest_match"] is True
    assert block["structural_integrity"]["computed"] == SHA256_HASH
    # The signature rules read the same block for a catalog scope: this
    # synthetic signer has no timestamp, so the timestamp rule fires on it.
    assert check_authenticode("member.dll", metadata, {}) is True
    assert check_weak_signature_digest("member.dll", metadata, {}) is True
    assert check_signature_not_timestamped("member.dll", metadata, {}) is not True
    assert metadata["security_properties"]["authenticode_scope"] == "catalog"
    assert "authenticode_scope" not in metadata["security_properties_gaps"]


def test_apply_negative_on_complete_index_fires_the_rule(tmp_path):
    _write_cat(
        tmp_path,
        "other.cat",
        _cat_content_info(_modern_ctl([_modern_member_entry(SHA1_HASH)])),
    )
    index = build_catalog_index(str(tmp_path))
    assert index["complete"] is True
    # Neither of this file's hashes is a member of the index.
    metadata = _member_metadata("e" * 40, "f" * 64)
    apply_catalog_signature(metadata, index)
    block = metadata["code_signature"]
    assert block["scope"] == "none"
    assert block["catalog_lookup"] == "negative"
    result = check_authenticode("member.dll", metadata, {})
    assert result is not True
    assert str(tmp_path) in result


def test_apply_embedded_scope_is_never_touched(tmp_path):
    _write_cat(
        tmp_path,
        "hit.cat",
        _cat_content_info(_modern_ctl([_modern_member_entry(SHA256_HASH)])),
    )
    index = build_catalog_index(str(tmp_path))
    metadata = _member_metadata(SHA1_HASH, SHA256_HASH)
    metadata["code_signature"].update({"scope": "embedded", "parse_status": "parsed"})
    apply_catalog_signature(metadata, index)
    block = metadata["code_signature"]
    assert block["scope"] == "embedded"
    # Untouched: the lookup stays exactly what the parse wrote, and no
    # catalog fact is attached to an embedded-scope block.
    assert block["catalog_lookup"] == "not_performed"
    assert "catalog_directory" not in block
    assert "catalog" not in block


def test_apply_without_reference_hash_is_not_performed(tmp_path):
    _write_cat(
        tmp_path,
        "hit.cat",
        _cat_content_info(_modern_ctl([_modern_member_entry(SHA256_HASH)])),
    )
    index = build_catalog_index(str(tmp_path))
    metadata = _member_metadata(SHA1_HASH, SHA256_HASH)
    metadata["authenticode"] = {}
    apply_catalog_signature(metadata, index)
    block = metadata["code_signature"]
    assert block["catalog_lookup"] == "not_performed"
    assert block["catalog_lookup_error"] == "authentihash_unavailable"
    assert check_authenticode("member.dll", metadata, {}) is True


def test_non_pe_metadata_is_ignored():
    metadata = _member_metadata(SHA1_HASH, SHA256_HASH)
    metadata["binary_type"] = "ELF"
    apply_catalog_signature(metadata, {"complete": True, "catalog_dir": "/", "entries": {}})
    assert metadata["code_signature"]["catalog_lookup"] == "not_performed"
