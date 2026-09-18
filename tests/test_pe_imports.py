# SPDX-License-Identifier: Apache-2.0
"""Tests for PE import depth: delay-load, ordinals, apisets (W1.2, 01/A.6).

The import and delay-import tables are hand-built the way the Windows linker
lays them out, the same discipline test_pe_debug uses for the debug
directory, so every variant ground rule 10 asks for exists as a fixture:
named imports, ordinal imports (snapshot-covered and not), api sets
(resolved and unresolved), delay-load directories (named and ordinal), and
forwarded exports.
"""

import struct

from blint.lib.binary import parse
from blint.lib.pe_imports import (
    RESOLUTION_ORDINAL_TABLE,
    RESOLUTION_UNRESOLVED,
    TAG_DELAYLOAD,
    TAG_FORWARDER,
    apiset_host,
    delay_import_hash,
    forwarder_target,
    is_apiset,
    normalize_forwarder_library,
    ordinal_name,
    summarize_resolution,
)

SECTION_RVA = 0x1000
SECTION_RAW = 0x1000
HEADERS_END = 0x400


def _pe64_image(data_directories: dict[int, tuple[int, int]], body: bytes, sections=None):
    """A minimal PE32+ image with the given data directories set.

    ``body`` is placed at the start of the single mapped section; pass
    ``sections`` as (name, virtual_size, raw_size, characteristics) tuples
    for images needing more than one.
    """
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x0022)
    optional = bytearray(0xF0)
    struct.pack_into("<H", optional, 0, 0x20B)
    struct.pack_into("<I", optional, 32, 0x1000)  # section_alignment
    struct.pack_into("<I", optional, 36, 0x200)  # file_alignment
    struct.pack_into("<H", optional, 68, 3)  # subsystem console
    struct.pack_into("<I", optional, 108, 16)  # numberof_rva_and_size
    for index, (rva, size) in data_directories.items():
        struct.pack_into("<II", optional, 112 + index * 8, rva, size)
    sec_headers = b""
    if sections is None:
        sections = [(b".rdata\0\0", 0x1000, SECTION_RAW, 0x40000040)]
        sec_headers = struct.pack(
            "<8sIIIIIIHHI",
            b".rdata\0\0", 0x1000, SECTION_RVA, SECTION_RAW, HEADERS_END, 0, 0, 0, 0,
            0x40000040,
        )
        total_virtual = SECTION_RVA + SECTION_RAW
    else:
        rva = SECTION_RVA
        raw = HEADERS_END
        for name, virtual_size, raw_size, chars in sections:
            sec_headers += struct.pack(
                "<8sIIIIIIHHI", name, virtual_size, rva, raw_size, raw, 0, 0, 0, 0, chars
            )
            rva += 0x1000
            raw += raw_size
        total_virtual = rva
    struct.pack_into("<I", optional, 56, total_virtual)
    return b"".join([bytes(dos), b"PE\x00\0", coff, bytes(optional), sec_headers]).ljust(
        HEADERS_END, b"\x00"
    ) + bytes(body.ljust(SECTION_RAW, b"\x00"))


def _build_import_directory(cursor: int, dll_name: bytes, functions: list, ordinals: list):
    """One IMAGE_IMPORT_DESCRIPTOR's tables: (descriptor_bytes, pieces).

    ``functions`` are named imports, ``ordinals`` are ordinal numbers. The
    ILT and IAT carry the same entries; a set high bit marks an ordinal.
    """
    entries = []
    for name in functions:
        entries.append(("name", name))
    for ordinal in ordinals:
        entries.append(("ordinal", ordinal))
    hint_size = sum(2 + len(n) + 1 + 1 for _kind, n in entries if _kind == "name")
    name_off = cursor
    after_name = cursor + len(dll_name) + 1
    hint_off = after_name
    iltoff = hint_off + hint_size
    # 4-align the IAT: the loader and LIEF read it through aligned pointers.
    iatoff = iltoff + 8 * (len(entries) + 1)
    iatoff = (iatoff + 3) & ~3
    iltable = b""
    iattable = b""
    hoff = hint_off
    for kind, value in entries:
        if kind == "name":
            hint = 1
            entry = (SECTION_RVA + hoff) | 0  # hint/name RVA, ordinal bit clear
            hname = struct.pack("<H", hint) + value + b"\x00"
            if len(hname) % 2:
                hname += b"\x00"
            hoff += len(hname)
        else:
            entry = 0x8000000000000000 | value
        iltable += struct.pack("<Q", entry)
        iattable += struct.pack("<Q", entry)
    iltable += struct.pack("<Q", 0)
    iattable += struct.pack("<Q", 0)
    descriptor = struct.pack(
        "<IIIII",
        SECTION_RVA + iltoff,  # OriginalFirstThunk
        0,  # TimeDateStamp
        0,  # ForwarderChain
        SECTION_RVA + name_off,  # Name
        SECTION_RVA + iatoff,  # FirstThunk
    )
    pieces = [
        (name_off, dll_name + b"\x00"),
    ]
    hoff = hint_off
    for kind, value in entries:
        if kind == "name":
            hname = struct.pack("<H", 1) + value + b"\x00"
            if len(hname) % 2:
                hname += b"\x00"
            pieces.append((hoff, hname))
            hoff += len(hname)
    pieces.append((iltoff, iltable))
    pieces.append((iatoff, iattable))
    return descriptor, pieces, iatoff + 8 * (len(entries) + 1)


def _imports_image(dll_specs: list[tuple[bytes, list, list]]) -> bytes:
    """An image whose import directory holds the given DLLs."""
    cursor = 0x40
    all_pieces = []
    descriptors = b""
    for dll_name, functions, ordinals in dll_specs:
        descriptor, pieces, cursor = _build_import_directory(cursor, dll_name, functions, ordinals)
        descriptors += descriptor
        all_pieces += pieces
    descriptors += struct.pack("<IIIII", 0, 0, 0, 0, 0)
    directory_rva = SECTION_RVA + cursor
    body = bytearray(SECTION_RAW)
    body[cursor : cursor + len(descriptors)] = descriptors
    for offset, data in all_pieces:
        body[offset : offset + len(data)] = data
    return _pe64_image({1: (directory_rva, len(descriptors))}, bytes(body))


def _delay_imports_image(dll_specs: list[tuple[bytes, list, list]]) -> bytes:
    """An image whose delay-load directory holds the given DLLs.

    Modern (grAttrs = ds_VA) ImgDelayDescr layout: the address fields are
    virtual addresses, the IAT/INT carry the same hint/name or ordinal
    entries an import table would.
    """
    cursor = 0x40
    all_pieces = []
    descriptors = b""
    for dll_name, functions, ordinals in dll_specs:
        entries = [("name", n) for n in functions] + [("ordinal", o) for o in ordinals]
        name_off = cursor
        after_name = cursor + len(dll_name) + 1
        hint_off = after_name
        hint_size = sum(2 + len(n) + 2 for kind, n in entries if kind == "name")
        int_off = hint_off + hint_size
        iat_off = int_off + 8 * (len(entries) + 1)
        hoff = hint_off
        intable = b""
        iattable = b""
        for kind, value in entries:
            if kind == "name":
                entry = SECTION_RVA + hoff
                hname = struct.pack("<H", 1) + value + b"\x00"
                if len(hname) % 2:
                    hname += b"\x00"
                hoff += len(hname)
            else:
                entry = 0x8000000000000000 | value
            intable += struct.pack("<Q", entry)
            iattable += struct.pack("<Q", entry)
        intable += struct.pack("<Q", 0)
        iattable += struct.pack("<Q", 0)
        descriptors += struct.pack(
            "<IIIIIIII",
            0,  # grAttrs: fields are RVAs
            SECTION_RVA + name_off,
            SECTION_RVA + 0x800,  # phmod scratch
            SECTION_RVA + iat_off,
            SECTION_RVA + int_off,
            0,
            0,
            0,
        )
        pieces = [(name_off, dll_name + b"\x00")]
        hoff = hint_off
        for kind, value in entries:
            if kind == "name":
                hname = struct.pack("<H", 1) + value + b"\x00"
                if len(hname) % 2:
                    hname += b"\x00"
                pieces.append((hoff, hname))
                hoff += len(hname)
        pieces.append((int_off, intable))
        pieces.append((iat_off, iattable))
        all_pieces += pieces
        cursor = iat_off + 8 * (len(entries) + 1) + 8
    descriptors += struct.pack("<IIIIIIII", *([0] * 8))
    directory_rva = SECTION_RVA + cursor
    body = bytearray(SECTION_RAW)
    body[cursor : cursor + len(descriptors)] = descriptors
    for offset, data in all_pieces:
        body[offset : offset + len(data)] = data
    return _pe64_image({13: (directory_rva, len(descriptors))}, bytes(body))


def _forwarder_exports_image(forwarders: list[tuple[str, str]], names: list[str]) -> bytes:
    """An image whose export table forwards the given (library, function)
    pairs and exports the plain ``names`` as ordinary functions."""
    cursor = 0x40
    export_rva = SECTION_RVA + cursor
    dll_name = b"forwarder.dll\x00"
    fwd_strings = b"\x00".join(f"{lib}.{func}".encode() for lib, func in forwarders) + b"\x00"
    name_strings = b"\x00".join(n.encode() for n in names) + b"\x00"
    # Layout: export directory (40) | dll name | forwarder strings |
    # name strings | EAT | name-pointer table | ordinal table
    off = cursor + 40
    dll_name_off = off
    off += len(dll_name)
    fwd_off = off
    off += len(fwd_strings)
    name_strings_off = off
    off += len(name_strings)
    eat_off = off
    count = len(forwarders) + len(names)
    off += 4 * count
    npt_off = off
    off += 4 * len(names)
    ord_off = off
    body = bytearray(SECTION_RAW)
    body[cursor : cursor + 40] = struct.pack(
        "<IIHHIIIIIII",
        0,  # characteristics
        1700000000,  # timestamp
        0,  # major version
        0,  # minor version
        SECTION_RVA + dll_name_off,  # Name
        1,  # ordinal base
        count,  # NumberOfFunctions
        len(names),  # NumberOfNames
        SECTION_RVA + eat_off,  # AddressOfFunctions
        SECTION_RVA + npt_off,  # AddressOfNames
        SECTION_RVA + ord_off,  # AddressOfNameOrdinals
    )
    body[dll_name_off : dll_name_off + len(dll_name)] = dll_name
    body[fwd_off : fwd_off + len(fwd_strings)] = fwd_strings
    body[name_strings_off : name_strings_off + len(name_strings)] = name_strings
    eat = b""
    for index, (lib, func) in enumerate(forwarders):
        # A forwarder is an EAT entry pointing at the forwarder string.
        eat += struct.pack(
            "<I",
            SECTION_RVA + fwd_off + sum(len(f"{l}.{f}") + 1 for l, f in forwarders[:index]),
        )
    for index in range(len(names)):
        eat += struct.pack("<I", SECTION_RVA + 0x20 + index * 4)
    body[eat_off : eat_off + len(eat)] = eat
    npt = b""
    for index, _name in enumerate(names):
        npt += struct.pack(
            "<I",
            SECTION_RVA + name_strings_off + sum(len(n) + 1 for n in names[:index]),
        )
    body[npt_off : npt_off + len(npt)] = npt
    ords = b"".join(struct.pack("<H", index) for index in range(count))
    body[ord_off : ord_off + len(ords)] = ords
    # The directory size must cover the whole table region: LIEF (and the
    # loader) classify an EAT entry as a forwarder only when its RVA lands
    # inside the export directory's declared bounds.
    return _pe64_image({0: (export_rva, ord_off + len(ords) - cursor)}, bytes(body))


def test_apiset_host_resolution_and_fallback():
    # Ground-truth pairs: the CRT contract is documented by Microsoft, the
    # synch contract is proven by dumpbin /exports of the downlevel stub.
    assert apiset_host("api-ms-win-crt-runtime-l1-1-0.dll") == "ucrtbase.dll"
    assert apiset_host("API-MS-WIN-CORE-SYNCH-L1-1-0.DLL") == "kernel32.dll"
    # A contract newer than the snapshot stays unresolved, by design.
    assert apiset_host("api-ms-win-core-future-l9-9-9.dll") is None
    # Not a contract at all.
    assert apiset_host("kernel32.dll") is None
    assert is_apiset("ext-ms-win-something-l1-1-0.dll")
    assert not is_apiset("ws2_32.dll")


def test_ordinal_name_lookups():
    # dumpbin /exports ws2_32.dll: ordinal 3 is closesocket.
    assert ordinal_name("WS2_32.dll", 3) == "closesocket"
    assert ordinal_name("oleaut32.dll", 2) == "SysAllocString"
    # A DLL outside the snapshot never answers.
    assert ordinal_name("wldap32.dll", 54) is None
    # An ordinal outside the covered range never answers.
    assert ordinal_name("ws2_32.dll", 40001) is None


def test_ordinal_imports_resolved_and_unresolved(tmp_path):
    """Named and ordinal imports in one table; the covered ordinal resolves
    through the snapshot and the uncovered one stays an ordinal (rule 14:
    the two outcomes never merge)."""
    image = _imports_image(
        [
            (b"WS2_32.dll", [], [3]),
            (b"WLDAP32.dll", [], [54]),
            (b"kernel32.dll", [b"CreateFileW"], []),
        ]
    )
    path = tmp_path / "imports.exe"
    path.write_bytes(image)
    md = parse(str(path), False)
    by_dll = {}
    for entry in md["imports"]:
        by_dll.setdefault(entry["name"].split("::")[0], []).append(entry)
    resolved = by_dll["WS2_32.dll"][0]
    assert resolved["short_name"] == "closesocket"
    assert resolved["resolution"] == RESOLUTION_ORDINAL_TABLE
    assert resolved["ordinal"] == 3
    unresolved = by_dll["WLDAP32.dll"][0]
    assert unresolved["short_name"] == "#54"
    assert unresolved["resolution"] == RESOLUTION_UNRESOLVED
    assert unresolved["ordinal"] == 54
    named = by_dll["kernel32.dll"][0]
    assert named["short_name"] == "CreateFileW"
    assert "resolution" not in named
    # An all-ordinal DLL is still a declared dependency.
    names = {entry["name"] for entry in md["dynamic_entries"]}
    assert {"WS2_32.dll", "WLDAP32.dll", "kernel32.dll"} <= names


def test_apiset_resolution_names_the_host(tmp_path):
    image = _imports_image(
        [
            (b"api-ms-win-crt-runtime-l1-1-0.dll", [b"_initterm"], []),
            (b"api-ms-win-core-future-l9-9-9.dll", [b"FutureFunc"], []),
        ]
    )
    path = tmp_path / "apiset.exe"
    path.write_bytes(image)
    md = parse(str(path), False)
    resolved = md["imports"][0]
    assert resolved["name"] == "ucrtbase.dll::_initterm"
    assert resolved["apiset"] == "api-ms-win-crt-runtime-l1-1-0.dll"
    unresolved = md["imports"][1]
    assert unresolved["name"] == "api-ms-win-core-future-l9-9-9.dll::FutureFunc"
    assert "apiset" not in unresolved
    # The dependency list carries the host, with the contract beside it.
    host_entry = next(e for e in md["dynamic_entries"] if e["name"] == "ucrtbase.dll")
    assert host_entry["apisets"] == ["api-ms-win-crt-runtime-l1-1-0.dll"]
    assert any(
        e["name"] == "api-ms-win-core-future-l9-9-9.dll" and "apisets" not in e
        for e in md["dynamic_entries"]
    )
    summary = md["import_resolution"]
    assert summary["apisets_resolved"] == 1
    assert summary["apisets_unresolved"] == 1


def test_delay_imports_are_their_own_table(tmp_path):
    image = _delay_imports_image(
        [
            (b"OLEAUT32.dll", [], [2]),
            (b"wintrust.dll", [b"WTHelperProvDataFromStateData"], []),
        ]
    )
    path = tmp_path / "delay.exe"
    path.write_bytes(image)
    md = parse(str(path), False)
    # Never merged: regular imports stay empty, delay imports carry both.
    assert md["imports"] == []
    delay_names = [entry["name"] for entry in md["delay_imports"]]
    assert "OLEAUT32.dll::SysAllocString" in delay_names
    assert "wintrust.dll::WTHelperProvDataFromStateData" in delay_names
    ordinal_entry = next(e for e in md["delay_imports"] if e.get("ordinal"))
    assert ordinal_entry["resolution"] == RESOLUTION_ORDINAL_TABLE
    # The delay table gets its own hash, distinct from the empty import hash.
    assert md["delay_import_hash"] == delay_import_hash(md["delay_imports"])
    assert md["import_hash"] != md["delay_import_hash"]
    # The dependency list tags the delay-loaded DLL.
    entry = next(
        e for e in md["dynamic_entries"] if e["name"].lower() == "oleaut32.dll"
    )
    assert entry["tag"] == TAG_DELAYLOAD


def test_delay_import_hash_differs_by_content():
    assert delay_import_hash([{"name": "a.dll::x"}]) != delay_import_hash(
        [{"name": "a.dll::y"}]
    )
    assert delay_import_hash([]) == ""


def test_forwarder_exports_name_the_target(tmp_path):
    image = _forwarder_exports_image(
        [("NTDLL", "RtlAllocHeap")], ["LocalOnly"]
    )
    path = tmp_path / "fwd.exe"
    path.write_bytes(image)
    md = parse(str(path), False)
    forwarded = [e for e in md["exports"] if e.get("is_forwarded")]
    assert forwarded, "the forwarder export must be parsed"
    assert forwarded[0]["forwarded_to"] == "NTDLL.RtlAllocHeap"
    assert forwarded[0]["fwd_library"] == "NTDLL"
    # The forward target joins the dependency list as its own kind.
    entry = next(e for e in md["dynamic_entries"] if e["name"] == "ntdll.dll")
    assert entry["tag"] == TAG_FORWARDER
    assert md["forwarder_targets"] == ["ntdll.dll"]


def test_forwarder_targets_feed_the_dependency_graph(tmp_path):
    from blint.lib.binary import analyze_import_deps

    image = _forwarder_exports_image([("NTDLL", "RtlAllocHeap")], ["LocalOnly"])
    path = tmp_path / "fwd2.exe"
    path.write_bytes(image)
    md = parse(str(path), False)
    graph = analyze_import_deps(md)
    target = graph["libraries"]["ntdll.dll"]
    assert target["type"] == "forwarder_target"
    # Not read as a symbol supplier: nothing was imported from it.
    assert target["imported_symbols"] == []


def test_summarize_resolution_counts_are_exact():
    rows = [
        {"name": "a.dll::x", "resolution": RESOLUTION_ORDINAL_TABLE},
        {"name": "a.dll::#5", "resolution": RESOLUTION_UNRESOLVED},
        {"name": "b.dll::y"},
    ]
    summary = summarize_resolution(rows, [], [[{"name": "a.dll", "tag": "NEEDED"}]])
    assert summary["ordinals_resolved"] == 1
    assert summary["ordinals_unresolved"] == 1
    assert summary["apisets_resolved"] == 0


def test_forwarder_helpers():
    assert forwarder_target("NTDLL", "RtlAllocHeap") == "NTDLL.RtlAllocHeap"
    assert forwarder_target("", "x") == ""
    assert normalize_forwarder_library("NTDLL") == "ntdll.dll"
    assert normalize_forwarder_library("WS2_32.dll") == "ws2_32.dll"


def test_real_fixture_named_imports_keep_their_shape():
    """The W1.2 rewrite must leave the historical entry shape intact on a
    real MSVC image (ground rule 29 shape check; full ground truth against
    dumpbin is pasted in the packet commit)."""
    md = parse("tests/data/pe/msvc-hello-x64.exe", False)
    assert md["imports"], "the real fixture must import something"
    for entry in md["imports"][:20]:
        assert "::" in entry["name"]
        assert entry["short_name"]
        assert "resolution" not in entry  # named imports carry no verdict
    for entry in md["dynamic_entries"]:
        assert entry["tag"] == "NEEDED"


def test_tables_ship_more_rows_than_any_sample_cap():
    """Ground rule 33: the snapshots are generated data larger than the
    summary's sample cap, so the cap can never hide a coverage failure."""
    import importlib.resources

    import yaml

    for filename in ("pe_apisets.yml", "pe_ordinals.yml"):
        with importlib.resources.files("blint.data").joinpath(filename).open(
            "r", encoding="utf-8"
        ) as handle:
            data = yaml.safe_load(handle)
        assert data.get("source_build")
    with importlib.resources.files("blint.data").joinpath("pe_apisets.yml").open(
        "r", encoding="utf-8"
    ) as handle:
        apisets = yaml.safe_load(handle)
    with importlib.resources.files("blint.data").joinpath("pe_ordinals.yml").open(
        "r", encoding="utf-8"
    ) as handle:
        ordinals = yaml.safe_load(handle)
    assert len(apisets["api_sets"]) > 800
    assert sum(len(v) for v in ordinals["ordinals"].values()) > 1000
