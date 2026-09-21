# SPDX-License-Identifier: Apache-2.0
"""Catalog signing (W2.3; 02/B): ``.cat`` files as a first-class input.

Most of ``C:\\Windows\\System32`` carries no embedded Authenticode blob;
those files are signed by catalog files under ``C:\\Windows\\System32\\CatRoot``
— PKCS#7 ``SignedData`` whose encapsulated content is a Certificate Trust
List (``1.3.6.1.4.1.311.10.1``) listing one entry per member file, keyed by
the member's hash. This module parses those files, builds a hash → catalog
index over a supplied directory (``blint --catalog-dir``), and answers one
question per PE: is your authentihash a member of one of these catalogs?

The CMS structures are walked by the *same* code the embedded block uses
(``pe_signature``): the catalog's signer, chain and timestamp come out of
``walk_signature_list``, so ``code_signature.signatures`` has exactly one
shape for both scopes and a consumer reads one block (rule 21). A second
CMS walk in a second module is the thing not to build.

Three states, and the honesty each requires (rules 11/14):

- no ``--catalog-dir``: ``catalog_lookup: "not_performed"`` — a
  catalog-signed file cannot be distinguished from an unsigned one, so
  nothing here may read ``is_signed: false``.
- a directory supplied and the hash found: ``scope: "catalog"`` with the
  catalog's signer, the catalog's path, and the member-hash algorithm the
  match was made on.
- a directory supplied and the hash not found: ``catalog_lookup:
  "negative"`` — the third state, the only evidence a file is genuinely
  unsigned. It is only reachable on a *complete* index: an index that
  refused or truncated any catalog cannot prove absence, and reports
  ``catalog_lookup: "index_incomplete"`` instead. "Not found in the part
  of the index we built" is not "not signed". A negative is likewise the
  only state from which ``signing_class: "unsigned"`` is claimed (02/C);
  a positive match derives the class from the catalog's own signer
  through the same walk, and every other state leaves the class absent.

The member hash the lookup probes is the file's authentihash — the same
exclusions (PE checksum, security directory) both Authenticode and
``CryptCATAdminCalcHashFromFileHandle`` apply — as computed per algorithm
by ``parse_pe_authenticode``. Catalogs do not name an entry's hash
algorithm in band; the algorithm is implied by the digest width and
recorded from it.

Ground rule 30: a ``.cat`` file is untrusted input and a catalog directory
is an unbounded number of them. Every limit below ships a fixture that
exceeds it; refusal is a recorded degradation that marks the index
incomplete, never a silent skip and never an exception through the parse.
Everything returned is plain JSON types (str/int/bool/None/dict/list), so
the parse cache can serialize it.
"""

import os

from blint.lib.pe_signature import (
    OID_SIGNED_DATA,
    _asn1_time,
    _ber_read,
    _decode_string,
    _oid_decode,
    _parse_content_info,
    _parse_signed_data,
    _SignatureFormatError,
    apply_signing_class,
    walk_signature_list,
)
from blint.logger import LOG

# --- OIDs this module keys on. Numbers, never a dependency's enum names. --
OID_CTL = "1.3.6.1.4.1.311.10.1"
OID_SPC_INDIRECT_DATA = "1.3.6.1.4.1.311.2.1.4"
# Catalog attribute OIDs (mscat.h), named where the attribute is understood;
# unknown ones pass through as dotted strings. Observed on real Windows 11
# package catalogs: 12.2.1 (OSAttr) at the CTL level and 12.2.3 on every
# member entry, with 1.3.6.1.4.1.311.2.1.4 (SpcIndirectData) carrying the
# member digest on the SHA-256 entry of each pair.
CTL_ATTRIBUTE_NAMES = {
    "1.3.6.1.4.1.311.12.1.1": "catalogNameValue",
    "1.3.6.1.4.1.311.12.1.2": "catalogMemberInfo",
    "1.3.6.1.4.1.311.12.1.3": "catalogMemberInfo2",
    "1.3.6.1.4.1.311.12.2.1": "catalogNameValueOsAttr",
    "1.3.6.1.4.1.311.12.2.2": "catalogNameValueFile",
    "1.3.6.1.4.1.311.12.2.3": "catalogNameValueHash",
    "1.3.6.1.4.1.311.2.1.4": "spcIndirectData",
}
# The attribute naming the indirect member catalog: its presence on an
# entry means the entry describes a file of another .cat (indirect
# catalogs); the entry's hash is indexed all the same.
CATALOG_MEMBER_INFO = "1.3.6.1.4.1.311.12.1.2"

# Digest widths a catalog entry can carry; the algorithm is implied by the
# width (catalogs do not name it in band). Lookup probes only SHA-256 and
# SHA-1, the two Windows computes for catalog membership.
HASH_ALGORITHM_BY_WIDTH = {
    16: "MD5",
    20: "SHA1",
    32: "SHA256",
    48: "SHA384",
    64: "SHA512",
}

# --- Limits (ground rule 30: every cap ships a fixture that exceeds it,
# and every count beside a capped listing stays exact). ---------------------
# Real Windows 11 CatRoot: ~3,630 catalogs, ~109 MB total, largest ~1.3 MB,
# up to ~7k entries per catalog, ~150k distinct member hashes overall. The
# caps sit far above every real value while still bounding hostile input;
# tripping any of them marks the index incomplete, which turns every
# negative lookup into "index_incomplete" for the whole run.
MAX_CATALOG_FILE_BYTES = 32 * 1024 * 1024
MAX_CATALOG_MEMBERS = 65536
MAX_CATALOGS_INDEXED = 8192
MAX_INDEX_ENTRIES = 1_000_000
MAX_WALKED_FILES = 65536
# Member-name evidence is a capped sample; the count beside it stays exact.
MAX_MEMBER_NAMES = 16
# Degradation records listed beside the exact count.
MAX_DEGRADATIONS_LISTED = 32


class CatalogLimits:
    """The caps, injectable so hostile fixtures can exceed them.

    Production callers use the defaults; the tests prove refusal at small
    values and prove the default member cap with a fixture that exceeds it.
    """

    def __init__(
        self,
        max_catalog_file_bytes: int = MAX_CATALOG_FILE_BYTES,
        max_catalog_members: int = MAX_CATALOG_MEMBERS,
        max_catalogs_indexed: int = MAX_CATALOGS_INDEXED,
        max_index_entries: int = MAX_INDEX_ENTRIES,
        max_walked_files: int = MAX_WALKED_FILES,
    ) -> None:
        self.max_catalog_file_bytes = max_catalog_file_bytes
        self.max_catalog_members = max_catalog_members
        self.max_catalogs_indexed = max_catalogs_indexed
        self.max_index_entries = max_index_entries
        self.max_walked_files = max_walked_files


def _attribute_name(oid: str) -> str:
    return CTL_ATTRIBUTE_NAMES.get(oid, oid)


def _member_tag_hash(raw: bytes) -> tuple[str, str] | None:
    """A member hash from the classic entry's leading OCTET STRING.

    makecat-era catalogs (the full Windows store carries them beside the
    modern package catalogs) tag each member with the hash rendered as a
    NUL-terminated UTF-16 ASCII-hex string — the digest itself rides the
    entry's SpcIndirectData attribute. Returns (hex, algorithm) when the
    tag decodes to a hex digest of a known width, else None.
    """
    try:
        text = raw.decode("utf-16-le").rstrip("\x00")
    except UnicodeDecodeError:
        return None
    lowered = text.lower()
    if len(lowered) % 2 or not all(c in "0123456789abcdef" for c in lowered):
        return None
    algorithm = HASH_ALGORITHM_BY_WIDTH.get(len(lowered) // 2)
    if not algorithm:
        return None
    return lowered, algorithm


def _attribute_digest(value: bytes, depth: int = 0) -> tuple[str, str] | None:
    """The member digest inside an SpcIndirectData attribute value.

    The value is { data, messageDigest { alg, OCTET STRING } }; the digest
    is the last width-valid OCTET STRING in the tree. Widths beyond the
    known ones are recorded by width, never guessed into an algorithm."""
    if depth > 8:
        return None
    found: tuple[str, str] | None = None
    pos = 0
    end = len(value)
    while pos < end:
        try:
            tag, inner, pos = _ber_read(value, pos, end)
        except _SignatureFormatError:
            break
        if tag == 0x04 and 8 <= len(inner) <= 64:
            found = (inner.hex(), HASH_ALGORITHM_BY_WIDTH.get(len(inner), f"unknown_{len(inner)}B"))
        elif tag & 0x20:
            nested = _attribute_digest(inner, depth + 1)
            if nested:
                found = nested
    return found


def _attribute_strings(value: bytes, depth: int = 0) -> list[str]:
    """Strings found inside an attribute value, best effort.

    Catalog attribute values wrap names in SpcLink-style TLVs ([0]/BMPString,
    [2]-constructed, IA5String); real package catalogs mostly carry empty
    ones, classic makecat-era entries carry the member file name. Walk
    defensively and take what decodes — the names are evidence, never the
    match key.
    """
    if depth > 8 or not value:
        return []
    strings: list[str] = []
    pos = 0
    end = len(value)
    while pos < end:
        try:
            tag, content, pos = _ber_read(value, pos, end)
        except _SignatureFormatError:
            break
        if tag in (0x0C, 0x13, 0x16, 0x1E):
            text = _decode_string(tag, content)
            if text:
                strings.append(text)
        elif tag == 0x80:  # context-primitive SpcString
            if all(0x20 <= byte <= 0x7E for byte in content):
                strings.append(content.decode("ascii"))
            else:
                text = _decode_string(0x1E, content)
                if text:
                    strings.append(text)
        elif tag & 0x20:  # constructed: descend
            strings.extend(_attribute_strings(content, depth + 1))
    return strings


def _parse_ctl_entries(ctl_content: bytes, catalog: dict) -> list[list[str]]:
    """CTL member entries, all three layouts, by shape — not by position.

    Real Windows 11 package catalogs use a simplified CTL (entries in a
    plain SEQUENCE; every member appears twice, once per hash width) and
    the classic RFC 5283-style CTL (version INTEGER first, entries under
    [1] IMPLICIT) — both put each member in a SEQUENCE whose first child
    is the hash OCTET STRING and whose second is the attribute SET. The
    makecat-era printer/driver catalogs in the full store use a third
    shape: the leading OCTET STRING is the member's digest rendered as a
    NUL-terminated UTF-16 hex tag, and the digest bytes ride the entry's
    ``SpcIndirectData`` attribute — recognized by the same (OCTET STRING,
    SET) outline and resolved through ``_member_tag_hash`` /
    ``_attribute_digest``.

    The member count stays exact past the storage cap — the walk always
    finishes — while the returned hash list carries at most what
    ``_store_limit`` allows, flagged ``members_stored_capped``.
    """
    stored: list[list[str]] = []
    limit = catalog.pop("_store_limit")
    pos = 0
    end = len(ctl_content)
    member_count = 0
    undecodable = 0
    while pos < end:
        try:
            tag, value, pos = _ber_read(ctl_content, pos, end)
        except _SignatureFormatError:
            catalog["parse_error"] = "ctl_entries_truncated"
            # The walk stopped mid-stream: the count is a floor, not the
            # total, and the stored hashes are a sample of it (rule 33).
            catalog["members_truncated"] = True
            break
        if tag not in (0x30, 0xA1):
            continue
        try:
            children = []
            child_pos = 0
            child_end = len(value)
            while child_pos < child_end:
                child_tag, child_value, child_pos = _ber_read(value, child_pos, child_end)
                children.append((child_tag, child_value))
        except _SignatureFormatError:
            # A container whose declared length outruns its bytes (a hostile
            # or cut TLV) is a truncation, never a silently skipped entry
            # list: the catalog is malformed and its counts are floors.
            catalog["parse_error"] = catalog["parse_error"] or "ctl_entries_truncated"
            catalog["members_truncated"] = True
            continue
        for child_tag, child_value in children:
            if child_tag != 0x30:
                continue
            try:
                hash_tag, hash_value, entry_pos = _ber_read(child_value, 0, len(child_value))
                attrs_tag, attrs_value, _ = _ber_read(child_value, entry_pos, len(child_value))
            except _SignatureFormatError:
                continue
            if hash_tag != 0x04 or attrs_tag != 0x31:
                continue
            # A recognized member entry whatever carries the digest: the
            # modern shape hashes in the leading OCTET STRING, the classic
            # makecat shape tags the member with a hex-text digest there
            # and carries the bytes in the SpcIndirectData attribute.
            member_count += 1

            named = False
            indirect = False
            member_hash: tuple[str, str] | None = None
            attr_values: list[bytes] = []
            width = len(hash_value)
            if 8 <= width <= 64:
                member_hash = (hash_value.hex(), HASH_ALGORITHM_BY_WIDTH.get(width, f"unknown_{width}B"))
            else:
                member_hash = _member_tag_hash(hash_value)
            attr_pos = 0
            attr_end = len(attrs_value)
            while attr_pos < attr_end:
                try:
                    _, attribute, attr_pos = _ber_read(attrs_value, attr_pos, attr_end)
                    inner_pos = 0
                    inner_end = len(attribute)
                    oid = None
                    values: list[bytes] = []
                    while inner_pos < inner_end:
                        v_tag, v_value, inner_pos = _ber_read(attribute, inner_pos, inner_end)
                        if v_tag == 0x06 and oid is None:
                            oid = _oid_decode(v_value)
                        elif v_tag == 0x31:
                            values.append(v_value)
                    if oid is None:
                        continue
                    attr_values.extend(values)
                    name = _attribute_name(oid)
                    catalog["attribute_counts"][name] = (
                        catalog["attribute_counts"].get(name, 0) + 1
                    )
                    if oid == CATALOG_MEMBER_INFO:
                        indirect = True
                    for set_value in values:
                        texts = _attribute_strings(set_value)
                        if texts:
                            named = True
                            room = MAX_MEMBER_NAMES - len(catalog["member_names"])
                            if room > 0:
                                catalog["member_names"].extend(texts[:room])
                except _SignatureFormatError:
                    break
            if named:
                catalog["member_named_count"] += 1
            if indirect:
                catalog["indirect_member_count"] += 1
            if member_hash is None:
                # Classic shape: the digest is the messageDigest inside the
                # entry's SpcIndirectData attribute.
                for set_value in attr_values:
                    member_hash = _attribute_digest(set_value)
                    if member_hash:
                        break
            if member_hash is None:
                # A member entry by shape whose digest none of the three
                # layouts yielded. It is not in the index, so files it
                # covers cannot be found there — a different outcome from
                # the storage cap, and recorded as one (rule 14): both
                # mark the index incomplete, and conflating them would
                # report a cap that was never reached.
                undecodable += 1
                continue
            if len(stored) < limit:
                stored.append(list(member_hash))
    catalog["member_count"] = member_count
    if undecodable:
        catalog["members_undecodable"] = undecodable
    if member_count - undecodable > len(stored):
        catalog["members_stored_capped"] = True
    return stored


def _parse_ctl_header(ctl_content: bytes, catalog: dict) -> None:
    """CTL-level facts (usage OID, thisUpdate, list identifier): best effort
    and tolerant — the header's exact field order differs between the
    simplified and classic layouts, and none of it is the match key. The
    usage OID is only claimed when a version INTEGER precedes it (the
    classic layout); the simplified layout's leading SEQ-of-OID markers are
    catalog attributes, not a subject usage."""
    pos = 0
    end = len(ctl_content)
    seen_version = False
    while pos < end:
        try:
            tag, value, pos = _ber_read(ctl_content, pos, end)
        except _SignatureFormatError:
            return
        if tag == 0x02:
            seen_version = True
        elif tag == 0x30 and seen_version and "subject_usage_oid" not in catalog:
            try:
                oid_tag, oid_value, _ = _ber_read(value, 0, len(value))
                if oid_tag == 0x06:
                    catalog["subject_usage_oid"] = _oid_decode(oid_value)
            except _SignatureFormatError:
                continue
        elif tag in (0x17, 0x18) and "this_update" not in catalog:
            catalog["this_update"], _ = _asn1_time(tag, value)
        elif tag == 0x04 and "list_identifier_hex" not in catalog:
            catalog["list_identifier_hex"] = value.hex()


def parse_catalog_file(path: str, limits: CatalogLimits | None = None) -> dict:
    """Parse one ``.cat`` file: members, member hashes, signer, timestamp.

    Returns a JSON-safe dict; hostile input (truncated, cyclic, oversized
    DER) degrades to ``parse_status: "malformed"`` with a ``parse_error``,
    never an exception. The signer comes from the same
    ``code_signature.signatures`` shape the embedded block uses — same
    walk, same caps, same truncation discipline. A catalog whose members
    walked but whose signer could not be read stays ``parsed`` with
    ``signer_unreadable: true``: its hashes are still the OS's own.
    """
    limits = limits or CatalogLimits()
    catalog: dict = {
        "file": path,
        "parse_status": "malformed",
        "parse_error": None,
        "member_count": 0,
        "member_hashes_stored": 0,
        "member_named_count": 0,
        "indirect_member_count": 0,
        "attribute_counts": {},
        "member_names": [],
        "signatures": [],
        "signature_count": 0,
    }
    try:
        size = os.path.getsize(path)
    except OSError as e:
        catalog["parse_error"] = f"unreadable:{e}"
        return catalog
    if size > limits.max_catalog_file_bytes:
        catalog["parse_error"] = f"file_too_large:{size}"
        return catalog
    try:
        with open(path, "rb") as handle:
            der = handle.read()
    except OSError as e:
        catalog["parse_error"] = f"unreadable:{e}"
        return catalog
    if len(der) != size:
        catalog["parse_error"] = f"read_truncated:{len(der)}_of_{size}"
        return catalog

    try:
        # The catalog's signer/chain/timestamp through the shared walk — the
        # whole file is one ContentInfo, exactly like a WIN_CERTIFICATE blob.
        walk = walk_signature_list([der])
        catalog["signatures"] = walk["signatures"]
        catalog["signature_count"] = walk["signature_count"]
        catalog["weak_digest_only"] = walk["weak_digest_only"]
        if walk["signature_walk_truncated"]:
            catalog["signature_walk_truncated"] = True
        if walk["signature_errors"]:
            catalog["signature_errors"] = walk["signature_errors"]
        if walk["signature_count"] == 0:
            catalog["signer_unreadable"] = True

        content_type, payload = _parse_content_info(der)
        if content_type != OID_SIGNED_DATA or payload is None:
            catalog["parse_error"] = f"content_type:{content_type}"
            return catalog
        signed = _parse_signed_data(payload)
        if signed["content_type"] != OID_CTL or signed["content"] is None:
            catalog["parse_error"] = f"not_a_catalog:{signed['content_type']}"
            return catalog
        _parse_ctl_header(signed["content"], catalog)
        catalog["_store_limit"] = limits.max_catalog_members
        stored = _parse_ctl_entries(signed["content"], catalog)
        catalog["member_hashes_stored"] = len(stored)
        catalog["hashes"] = stored
        if not catalog["parse_error"]:
            catalog["parse_status"] = "parsed"
        return catalog
    except _SignatureFormatError as e:
        catalog["parse_error"] = str(e)
        return catalog
    except (IndexError, KeyError, TypeError, ValueError) as e:
        catalog["parse_error"] = f"{type(e).__name__}:{e}"
        return catalog


def build_catalog_index(catalog_dir: str, limits: CatalogLimits | None = None) -> dict:
    """Hash → catalog index over a directory of ``.cat`` files.

    Walks the tree without following directory symlinks (a cyclic tree
    cannot loop the walk), parses each catalog with ``parse_catalog_file``,
    and records every refusal or truncation as a degradation that marks the
    index incomplete. Counts beside capped listings stay exact: the walk
    always finishes, so the catalog and entry counts name the whole tree
    even when the caps stopped storing.

    An empty directory, a directory with no ``.cat`` files, or any refused
    or truncated catalog yields ``complete: False`` — a negative lookup
    against such an index reports ``index_incomplete``, never ``negative``.
    """
    limits = limits or CatalogLimits()
    index: dict = {
        "catalog_dir": catalog_dir,
        "complete": True,
        "catalog_count": 0,
        "catalogs_parsed": 0,
        "catalogs_indexed": 0,
        "catalogs_refused": 0,
        "files_walked": 0,
        "other_file_count": 0,
        "entry_count": 0,
        "indexed_entry_count": 0,
        "duplicate_entry_count": 0,
        "entries": {},
        "degradations": [],
        "degradation_count": 0,
        "limits": {
            "max_catalog_file_bytes": limits.max_catalog_file_bytes,
            "max_catalog_members": limits.max_catalog_members,
            "max_catalogs_indexed": limits.max_catalogs_indexed,
            "max_index_entries": limits.max_index_entries,
            "max_walked_files": limits.max_walked_files,
        },
    }

    def degrade(path: str, reason: str) -> None:
        index["degradation_count"] += 1
        index["complete"] = False
        if len(index["degradations"]) < MAX_DEGRADATIONS_LISTED:
            index["degradations"].append({"catalog": path, "reason": reason})

    catalog_paths: list[str] = []
    walked = 0
    walk_truncated = False
    for dirpath, dirnames, filenames in os.walk(catalog_dir, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            walked += 1
            if walked > limits.max_walked_files:
                walk_truncated = True
                break
            path = os.path.join(dirpath, name)
            if name.lower().endswith(".cat"):
                index["catalog_count"] += 1
                catalog_paths.append(path)
            else:
                index["other_file_count"] += 1
        if walk_truncated:
            break
    if walk_truncated:
        index["files_walked_truncated"] = True
        degrade(catalog_dir, "walk_truncated")
    if not index["catalog_count"]:
        degrade(catalog_dir, "no_catalog_files")

    for path in catalog_paths:
        catalog = parse_catalog_file(path, limits)
        index["entry_count"] += catalog["member_count"]
        if catalog["parse_status"] == "parsed":
            index["catalogs_parsed"] += 1
        else:
            index["catalogs_refused"] += 1
            degrade(path, catalog["parse_error"] or "malformed")
        if catalog.get("members_stored_capped") or catalog.get("members_truncated"):
            degrade(path, "member_cap_exceeded")
        if catalog.get("members_undecodable"):
            degrade(path, f"members_undecodable:{catalog['members_undecodable']}")
        if index["catalogs_indexed"] >= limits.max_catalogs_indexed:
            degrade(path, "catalog_cap_exceeded")
            continue
        hashes = catalog.get("hashes") or []
        if catalog["parse_status"] != "parsed" and not hashes:
            continue
        index["catalogs_indexed"] += 1
        for hex_hash, algorithm in hashes:
            if index["indexed_entry_count"] >= limits.max_index_entries:
                degrade(path, "index_entry_cap_exceeded")
                break
            if hex_hash in index["entries"]:
                index["duplicate_entry_count"] += 1
                continue
            index["entries"][hex_hash] = {"catalog": path, "algorithm": algorithm}
            index["indexed_entry_count"] += 1
    return index


def lookup_member(index: dict, sha256_hex: str | None, sha1_hex: str | None) -> dict | None:
    """The index entry for a file's authentihash, SHA-256 preferred.

    Windows computes both widths for catalog membership and modern catalogs
    carry both as sibling entries; the algorithm reported is the one the
    match was actually made on.
    """
    if not index:
        return None
    for algorithm, hex_hash in (("SHA256", sha256_hex), ("SHA1", sha1_hex)):
        if not hex_hash:
            continue
        entry = index["entries"].get(hex_hash.lower())
        if entry:
            return {
                "catalog": entry["catalog"],
                "member_hash": hex_hash.lower(),
                "member_hash_algorithm": algorithm,
            }
    return None


def _catalog_signature_facts(index: dict, catalog_path: str) -> dict:
    """The matched catalog's signer facts, parsed once per catalog and
    cached inside the index — a System32 scan matches hundreds of files
    against a handful of big catalogs."""
    cache = index.setdefault("_signature_cache", {})
    if catalog_path not in cache:
        catalog = parse_catalog_file(catalog_path)
        cache[catalog_path] = {
            "signatures": catalog.get("signatures", []),
            "signature_count": catalog.get("signature_count", 0),
            "weak_digest_only": catalog.get("weak_digest_only"),
            "signature_walk_truncated": catalog.get("signature_walk_truncated", False),
            "signature_errors": catalog.get("signature_errors", []),
            "parse_error": catalog.get("parse_error"),
        }
    return cache[catalog_path]


def apply_catalog_signature(metadata: dict, index: dict | None) -> None:
    """Resolve ``scope: "none"`` against the catalog index, in place.

    Only ever runs with an index (a run without ``--catalog-dir`` leaves
    ``catalog_lookup: "not_performed"`` exactly as ``parse_pe_code_signature``
    wrote it). Embedded signatures win — Windows uses the embedded blob
    first, so a catalog result cannot upgrade or question it. A positive
    match repopulates ``signatures[]`` from the catalog's own signer so the
    block reads the same for both scopes (rule 21); ``parse_status`` then
    describes the signature facts the block now carries.
    """
    if not index:
        return
    if metadata.get("binary_type") != "PE":
        return
    block = metadata.get("code_signature")
    if not isinstance(block, dict) or block.get("scope") != "none":
        return
    block["catalog_directory"] = index["catalog_dir"]
    authenticode = metadata.get("authenticode") or {}
    sha256 = (authenticode.get("sha256_hash") or "").replace(":", "").lower() or None
    sha1 = (authenticode.get("sha1_hash") or "").replace(":", "").lower() or None
    if not sha256 and not sha1:
        block["catalog_lookup"] = "not_performed"
        block["catalog_lookup_error"] = "authentihash_unavailable"
        return
    match = lookup_member(index, sha256, sha1)
    if match is None:
        # Only the *negative* needs a complete index. "Not found in the part
        # of the index we built" is not "not signed"; finding the member is
        # proof either way, so the lookup runs first and an incomplete index
        # still answers positively for every file it did index.
        block["catalog_lookup"] = "negative" if index["complete"] else "index_incomplete"
        if block["catalog_lookup"] == "negative":
            # The one state from which "unsigned" may be claimed (02/C): the
            # lookup was performed against a complete index and the file is
            # in none of its catalogs. Every other state leaves the class
            # absent, and absence means undetermined — never "unsigned".
            block["signing_class"] = "unsigned"
        return
    if not index["complete"]:
        # Stated on the positive too: the match stands, and the reader knows
        # the index behind it was not whole.
        block["catalog_index_incomplete"] = True
    catalog_path = match["catalog"]
    facts = _catalog_signature_facts(index, catalog_path)
    block["scope"] = "catalog"
    block["catalog_lookup"] = "positive"
    block["catalog"] = match
    if facts["signatures"]:
        # Shallow per-file copies: the facts are cached across every file
        # that matches this catalog, and no consumer may mutate shared
        # signature entries.
        block["signatures"] = [dict(sig) for sig in facts["signatures"]]
        block["signature_count"] = facts["signature_count"]
        block["weak_digest_only"] = facts["weak_digest_only"]
        if facts["signature_walk_truncated"]:
            block["signature_walk_truncated"] = True
        # The block now carries parsed signature facts (from the catalog —
        # scope says where from), so the timestamp/digest rules read it.
        block["parse_status"] = "parsed"
        # The signing class derives from the catalog's own signer the same
        # way it derives from an embedded signature — same walk, same
        # caps, same truncation withholding.
        apply_signing_class(block, facts["signature_walk_truncated"])
        block["structural_integrity"] = {
            "digest_match": True,
            "algorithm": match["member_hash_algorithm"],
            "computed": sha256 if match["member_hash_algorithm"] == "SHA256" else sha1,
            "embedded": match["member_hash"],
        }
        properties = metadata.get("security_properties")
        if isinstance(properties, dict):
            properties["authenticode_scope"] = "catalog"
            page_hashed = any(
                (sig.get("page_hashes") or {}).get("present") for sig in facts["signatures"]
            )
            if page_hashed or not facts["signature_walk_truncated"]:
                properties["signed_page_hashes"] = page_hashed
            gaps = metadata.get("security_properties_gaps")
            if isinstance(gaps, list):
                resolved = ["authenticode_scope"]
                if page_hashed or not facts["signature_walk_truncated"]:
                    resolved.append("signed_page_hashes")
                metadata["security_properties_gaps"] = [
                    gap for gap in gaps if gap not in resolved
                ]
    else:
        # The member match is structural and real, but the catalog's signer
        # could not be read: say so rather than presenting an unsigned block.
        block["catalog_signature_errors"] = facts["signature_errors"] or [
            facts["parse_error"] or "signer_unreadable"
        ]
    LOG.debug(
        "Catalog match for %s: %s (%s)",
        metadata.get("name", "?"),
        os.path.basename(catalog_path),
        match["member_hash_algorithm"],
    )
