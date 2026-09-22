"""Tests for the CFBF reader (W4.2).

The builder below constructs real CFBF images byte-by-byte (header, FAT,
directory, stream data) so the hostile variants — a FAT chain that loops, a
chain pointing past the file, an oversized stream, a tree that loops — are
genuine format-shaped fixtures, not mocks (ground rules 10, 17, 30).
"""

import struct

import pytest

from blint.lib.cfbf import (
    ENDOFCHAIN,
    FREESECT,
    CfbfReader,
    is_cfbf_bytes,
    iter_summary_information,
    parse_cfbf,
)

SECTOR = 512
MINI_CUTOFF = 4096


def encode_name(name: str) -> bytes:
    return name.encode("utf-16-le") + b"\x00\x00"


def build_directory_entry(name: str, entry_type: int, color=1, left=0xFFFFFFFF, right=0xFFFFFFFF,
                          child=0xFFFFFFFF, start=ENDOFCHAIN, size=0, clsid=b"\x00" * 16):
    raw = encode_name(name)
    entry = raw + b"\x00" * (64 - len(raw))
    entry += struct.pack("<H", len(raw))  # includes the UTF-16 NUL
    entry += bytes([entry_type])
    entry += bytes([color])
    entry += struct.pack("<III", left, right, child)
    entry += clsid
    entry += b"\x00" * 20  # state bits (4) + creation/modified times (16)
    entry += struct.pack("<I", start)
    entry += struct.pack("<Q", size)
    assert len(entry) == 128, len(entry)
    return entry


def build_cfbf(
    streams: dict[str, bytes],
    *,
    chain_loop: str | None = None,
    out_of_range: str | None = None,
    early_terminate: str | None = None,
    oversized_declared: str | None = None,
    storages: dict[str, dict[str, bytes]] | None = None,
):
    """Build a minimal CFBF image with every stream at the root.

    ``storages`` adds real storage nesting: ``{"StorageName": {"stream":
    b"..."}}`` becomes a storage directory entry whose ``child`` points at
    its streams, which is how ``CfbfReader.tree()`` derives a path. Names
    in ``streams`` are literal entry names — a ``/`` in one is part of the
    name, not a hierarchy — so any fixture whose subject is the nesting
    itself (``.msg`` attachment storages, an MSI's substorages) must use
    this parameter or it tests a path the format cannot produce.

    Streams at or above the mini cutoff (4,096 bytes) get regular FAT
    sectors; smaller ones go into a mini stream with a mini FAT, like a
    real MSI or Office document. Hostile knobs: ``chain_loop`` makes the
    stream's FAT chain point at itself; ``out_of_range`` points its chain
    past the file; ``early_terminate`` ends its chain on a FREESECT;
    ``oversized_declared`` leaves the chain short but declares a huge size.
    """
    MINI = 64
    # Storage children are allocated exactly like root streams; the
    # composite key keeps them distinct while the directory section below
    # gives them their real parent.
    storages = storages or {}
    streams = dict(streams)
    for storage_name, children in storages.items():
        for child_name, payload in children.items():
            streams[f"{storage_name}\x01{child_name}"] = payload
    big_names = [n for n, v in streams.items() if len(v) >= MINI_CUTOFF]
    small_names = [n for n, v in streams.items() if len(v) < MINI_CUTOFF]

    # Mini stream: all small streams' bytes concatenated into mini sectors.
    mini_fat: list[int] = []
    mini_chain_starts: dict[str, int] = {}
    mini_stream = b""
    for name in small_names:
        payload = streams[name]
        blocks = max(1, (len(payload) + MINI - 1) // MINI)
        start = len(mini_fat) if payload else ENDOFCHAIN
        mini_chain_starts[name] = start if payload else ENDOFCHAIN
        for block in range(blocks):
            mini_fat.append(len(mini_fat) + 1 if block < blocks - 1 else ENDOFCHAIN)
        padded = payload.ljust(blocks * MINI, b"\x00")
        mini_stream += padded
    mini_stream_sectors = (len(mini_stream) + SECTOR - 1) // SECTOR
    if not mini_stream:
        mini_stream_sectors = 0

    # Regular sector allocation: mini-stream storage, big streams, then the
    # directory, then the FAT sectors, then the mini-FAT sectors.
    fat: list[int] = []

    def alloc_chain(payload: bytes, terminate=ENDOFCHAIN) -> tuple[int | None, list[bytes]]:
        # `fat` is mutated in place, never rebound, so no `nonlocal` —
        # CI's flake8 gate selects F82, which F824 matches by prefix.
        blocks = (len(payload) + SECTOR - 1) // SECTOR
        if not blocks:
            return None, []
        start = len(fat)
        chunk = []
        for block in range(blocks):
            fat.append(start + block + 1 if block < blocks - 1 else terminate)
            chunk.append(payload[block * SECTOR : (block + 1) * SECTOR].ljust(SECTOR, b"\x00"))
        return start, chunk

    mini_storage_start, mini_blocks = alloc_chain(mini_stream.ljust(mini_stream_sectors * SECTOR, b"\x00"))

    data_blocks: list[bytes] = []
    big_starts: dict[str, int | None] = {}
    for name in big_names:
        start, blocks = alloc_chain(streams[name])
        big_starts[name] = start
        data_blocks += blocks

    # Directory: root + all streams as root-tree siblings (right chain).
    root = build_directory_entry(
        "Root Entry", 5, start=mini_storage_start if mini_stream_sectors else ENDOFCHAIN,
        size=len(mini_stream), child=1,
    )
    def _start_of(name):
        if name in big_starts:
            start = big_starts[name]
        elif name in mini_chain_starts:
            start = mini_chain_starts[name]
        else:
            start = ENDOFCHAIN
        return ENDOFCHAIN if start is None else start

    root_names = [n for n in streams if "\x01" not in n]
    # Directory order: root, root-level streams, one entry per storage,
    # then each storage's children. `names` keeps the flat allocation
    # order the hostile knobs below index into.
    names = root_names + [f"{s}\x01{c}" for s, cs in storages.items() for c in cs]
    top_level = root_names + list(storages)
    dir_entries = [root]
    index_of = {name: position + 1 for position, name in enumerate(top_level)}
    child_index = len(top_level) + 1
    storage_children: dict[str, list[str]] = {}
    for storage_name, children in storages.items():
        storage_children[storage_name] = []
        for child_name in children:
            storage_children[storage_name].append(child_name)
            index_of[f"{storage_name}\x01{child_name}"] = child_index
            child_index += 1

    for position, name in enumerate(top_level):
        sibling = position + 2 if position + 2 <= len(top_level) else 0xFFFFFFFF
        if name in storages:
            first = storage_children[name]
            dir_entries.append(
                build_directory_entry(
                    name,
                    1,
                    right=sibling,
                    child=index_of[f"{name}\x01{first[0]}"] if first else 0xFFFFFFFF,
                )
            )
        else:
            dir_entries.append(
                build_directory_entry(
                    name, 2, right=sibling, start=_start_of(name), size=len(streams[name])
                )
            )
    for storage_name, children in storage_children.items():
        for position, child_name in enumerate(children):
            key = f"{storage_name}\x01{child_name}"
            nxt = children[position + 1] if position + 1 < len(children) else None
            dir_entries.append(
                build_directory_entry(
                    child_name,
                    2,
                    right=index_of[f"{storage_name}\x01{nxt}"] if nxt else 0xFFFFFFFF,
                    start=_start_of(key),
                    size=len(streams[key]),
                )
            )
    if oversized_declared in streams:
        position = names.index(oversized_declared) + 1
        entry = bytearray(dir_entries[position])
        struct.pack_into("<Q", entry, 120, 0xFFFFFFFF)
        dir_entries[position] = bytes(entry)
    if chain_loop in big_starts and big_starts[chain_loop] is not None:
        fat[big_starts[chain_loop]] = big_starts[chain_loop]
    if out_of_range in big_starts and big_starts[out_of_range] is not None:
        fat[big_starts[out_of_range]] = 0xFFFFFFF0
    if early_terminate in big_starts and big_starts[early_terminate] is not None:
        fat[big_starts[early_terminate]] = FREESECT

    directory = b"".join(dir_entries)
    directory_sectors = (len(directory) + SECTOR - 1) // SECTOR
    directory = directory.ljust(directory_sectors * SECTOR, b"\x00")

    fat_len_before = len(fat)
    dir_start = fat_len_before
    for offset in range(directory_sectors):
        fat.append(ENDOFCHAIN if offset == directory_sectors - 1 else dir_start + offset + 1)

    mini_fat_sectors = 0
    fat_sectors = max(1, (len(fat) * 4 + SECTOR - 1) // SECTOR)
    mini_fat_bytes = b""
    if mini_fat:
        mini_fat_bytes = b"".join(struct.pack("<I", v) for v in mini_fat)
        mini_fat_sectors = max(1, (len(mini_fat_bytes) + SECTOR - 1) // SECTOR)
        mini_fat_bytes = mini_fat_bytes.ljust(mini_fat_sectors * SECTOR, b"\xff")

    # Sector layout: [mini storage][big stream data][directory][FAT][miniFAT]
    fat_ids = list(range(dir_start + directory_sectors, dir_start + directory_sectors + fat_sectors))
    mini_fat_ids = list(range(fat_ids[-1] + 1, fat_ids[-1] + 1 + mini_fat_sectors)) if mini_fat_sectors else []
    # The mini-FAT sectors themselves chain through the regular FAT; the
    # chain values live at each sector's own FAT index.
    for offset, sector_id in enumerate(mini_fat_ids):
        while len(fat) <= sector_id:
            fat.append(FREESECT)
        fat[sector_id] = ENDOFCHAIN if offset == len(mini_fat_ids) - 1 else sector_id + 1

    header = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    header += b"\x00" * 16
    header += struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6)
    header += b"\x00" * 6
    header += struct.pack(
        "<IIIIIIIII", 0, fat_sectors, dir_start, 0, MINI_CUTOFF,
        mini_fat_ids[0] if mini_fat_ids else ENDOFCHAIN, mini_fat_sectors,
        ENDOFCHAIN, 0,
    )
    difat = [fat_ids[i] if i < len(fat_ids) else ENDOFCHAIN for i in range(109)]
    header += b"".join(struct.pack("<I", v) for v in difat)
    assert len(header) == 512

    image = bytearray(header)
    for block in mini_blocks:
        image += block
    for block in data_blocks:
        image += block
    image += directory
    for sector_id in fat_ids:
        image += b"\x00" * SECTOR
    for sector_id in mini_fat_ids:
        image += mini_fat_bytes[(sector_id - mini_fat_ids[0]) * SECTOR :][:SECTOR]
    # Patch the FAT sector contents now that their positions are fixed.
    fat_bytes = b"".join(struct.pack("<I", v) for v in fat)
    fat_bytes = fat_bytes.ljust(fat_sectors * SECTOR, b"\xff")
    for i, sector_id in enumerate(fat_ids):
        image[512 + sector_id * SECTOR : 512 + (sector_id + 1) * SECTOR] = fat_bytes[
            i * SECTOR : (i + 1) * SECTOR
        ]
    return bytes(image)


def test_is_cfbf_bytes():
    assert is_cfbf_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1rest")
    assert not is_cfbf_bytes(b"PK\x03\x04")


def test_parse_lists_root_streams():
    image = build_cfbf({"one": b"A" * 100, "sub": b"B" * 10})
    block = parse_cfbf(image)
    assert block["parse_status"] == "parsed"
    names = {e["name"] for e in block["entries"]}
    assert {"one", "sub"} <= names
    assert block["stream_count"] == 2
    assert block["degradations"] == []


def test_read_stream_round_trip():
    payload = bytes(range(256)) * 5  # 1280 bytes: regular FAT stream
    image = build_cfbf({"data": payload})
    reader = CfbfReader(image, [], [])
    entry = reader.find("data")
    assert entry is not None
    assert reader.read_entry(entry) == payload


def test_read_mini_stream_round_trip():
    payload = b"mini-stream-bytes"  # below the mini cutoff
    image = build_cfbf({"tiny": payload, "big": b"Z" * 6000})
    reader = CfbfReader(image, [], [])
    assert reader.find("tiny") is not None
    assert reader.read_entry(reader.find("tiny")) == payload
    assert reader.read_entry(reader.find("big")) == b"Z" * 6000


def test_chain_loop_is_a_named_degradation():
    image = build_cfbf({"looped": b"L" * 4096 * 2, "fine": b"ok"}, chain_loop="looped")
    reader = CfbfReader(image, [], [])
    entry = reader.find("looped")
    data = reader.read_entry(entry)
    assert "fat_chain_loop" in reader.degradations
    assert len(data) < 4096 * 2  # cut off at the loop, never absorbed
    # The rest of the tree is still listed and readable (rule 32).
    assert reader.find("fine") is not None
    assert reader.read_entry(reader.find("fine")) == b"ok"


def test_out_of_range_chain_is_a_named_degradation():
    image = build_cfbf({"bad": b"X" * 4096 * 2, "fine": b"ok"}, out_of_range="bad")
    reader = CfbfReader(image, [], [])
    data = reader.read_entry(reader.find("bad"))
    assert "sector_out_of_range" in reader.degradations
    # The chain yields what it safely saw (the first sector), then names
    # the break — never the whole payload and never silence.
    assert 0 < len(data) < 4096 * 2
    assert reader.find("fine") is not None


def test_early_chain_termination_is_named():
    image = build_cfbf({"cut": b"C" * 4096 * 2}, early_terminate="cut")
    reader = CfbfReader(image, [], [])
    reader.read_entry(reader.find("cut"))
    assert "chain_terminated_early" in reader.degradations


def test_oversized_declared_stream_refuses_by_name():
    image = build_cfbf({"huge": b"H" * 9000}, oversized_declared="huge")
    refusals: list[str] = []
    reader = CfbfReader(image, refusals, [])
    data = reader.read_entry(reader.find("huge"))
    assert data == b""
    assert "stream_size_exceeds_cap" in refusals


def test_not_a_cfbf_fails_cleanly():
    block = parse_cfbf(b"PK\x03\x04" + b"\x00" * 600)
    assert block["parse_status"] == "failed"


def test_summary_information_round_trip():
    """A hand-built \x05SummaryInformation property set decodes.

    The section layout mirrors the real 7z-x64.msi stream: the offset field
    names the section, the section starts with its size then its property
    count, and property value offsets are relative to the section start.
    """
    section_props = [
        (2, "title", "Installation Database"),
        (7, "template", "x64;1033"),
        (9, "revision_number", "{GUID-1}"),
    ]
    count = len(section_props)
    values_start = 8 + 8 * count  # size(4) + count(4) + entries, from so
    entries = b""
    values = b""
    running = values_start
    for prop_id, _name, value in section_props:
        encoded = value.encode("latin-1") + b"\x00"
        entries += struct.pack("<II", prop_id, running)
        running += 8 + len(encoded)
        running += (-running) % 4
        values += struct.pack("<HH", 0x1E, 0) + struct.pack("<I", len(encoded)) + encoded
        values += b"\x00" * ((-len(values)) % 4)
    body = struct.pack("<I", count) + entries + values
    section = struct.pack("<I", len(body) + 4) + body
    stream = struct.pack("<HHI", 0xFFFE, 0, 0x00020602)
    stream += b"\x00" * 16  # clsid
    stream += struct.pack("<I", 1)  # one property set
    stream += b"\xe0\x85\x9f\xf2\xf9\x4f\x68\x10\xab\x91\x08\x00\x2b\x27\xb3\xd9"
    stream += struct.pack("<II", len(stream) + 8, len(section))  # offset, size
    stream += section
    image = build_cfbf({"\x05SummaryInformation": stream})
    reader = CfbfReader(image, [], [])
    summary = iter_summary_information(reader)
    assert summary.get("title") == "Installation Database"
    assert summary.get("revision_number") == "{GUID-1}"


@pytest.mark.parametrize(
    "knob",
    ["chain_loop", "out_of_range", "early_terminate", "oversized_declared"],
)
def test_hostile_streams_never_raise(knob):
    image = build_cfbf({"hostile": b"H" * 9000, "bystander": b"b"}, **{knob: "hostile"})
    block = parse_cfbf(image)
    assert block["parse_status"] in ("parsed", "partial", "failed")
