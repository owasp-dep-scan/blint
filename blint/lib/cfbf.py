"""Pure-struct CFBF (Compound File Binary Format / OLE2) reader (W4.2).

MSI files, legacy Office documents (``.doc``/``.xls``/``.ppt``), Outlook
messages (``.msg``) and ``vbaProject.bin`` macro projects are all CFBF
storages: a header with FAT sector lists, a directory of storages and
streams, and a 64-byte mini-FAT for streams below the 4,096-byte cutoff.
One reader serves all of them (the plan's ``03/C`` first row); nothing here
imports LIEF or a Windows API, so a Linux run and a Windows run see the same
bytes (ground rule 31).

Sector-chain sanity is a first-class output (the plan: a malformed chain is
itself a finding, not a parse failure to swallow): every chain walk is
loop-detected and range-checked, and a violation records a named degradation
(``fat_chain_loop``, ``sector_out_of_range``, ``minifat_chain_loop``,
``chain_terminated_early``) beside whatever facts were read before it —
never a silent skip and never a raised exception that would lose the rest of
the tree.

Caps (ground rules 30/33) are measured on the corpus reference artifacts:
the 7z-x64.msi (2.0 MB, 512-byte sectors, 31 FAT sectors, 38 directory
entries, largest stream 1.9 MB) and the tier-4 Office documents: 4,096
directory entries (cap), 4,096 streams listed (cap), 256 MiB per-stream read
cap, 512 MiB total read budget, 64 MiB mini-stream cap. Hostile fixtures in
``tests/test_cfbf.py`` exceed each cap and assert the refusal by name. No
rule reads the capped listings — the listings bound output size; rule
verdicts read counted totals.
"""

# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
# SPDX-License-Identifier: Apache-2.0

import struct

CFBF_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
DIFSECT = 0xFFFFFFFC
NOSTREAM = 0xFFFFFFFF

# Entry types in the directory.
ENTRY_UNUSED = 0
ENTRY_STORAGE = 1
ENTRY_STREAM = 2
ENTRY_LOCKBYTES = 3
ENTRY_PROPERTY = 4
ENTRY_ROOT = 5

# Measured caps — see the module docstring for the measurement basis.
MAX_DIRECTORY_ENTRIES = 4096
MAX_STREAMS_LISTED = 4096
MAX_STREAM_READ = 256 * 1024 * 1024
MAX_TOTAL_STREAM_READ = 512 * 1024 * 1024
MAX_MINI_STREAM_READ = 64 * 1024 * 1024
# Directory tree depth: real CFBF trees are 2-3 deep (root/storage/stream).
MAX_TREE_DEPTH = 16


def is_cfbf_bytes(head: bytes) -> bool:
    """True when the bytes start with the CFBF magic."""
    return head[:8] == CFBF_MAGIC


def is_cfbf_file(path: str) -> bool:
    """True when the file starts with the CFBF magic."""
    try:
        with open(path, "rb") as handle:
            return is_cfbf_bytes(handle.read(8))
    except OSError:
        return False


class CfbfError(ValueError):
    """The file is not a CFBF storage at all (magic/header level)."""


class CfbfReader:
    """Bounded reader over one in-memory CFBF image.

    The caller owns the raw bytes (a few MB for any real MSI or Office
    document; callers read the file under their own container budget).
    """

    def __init__(self, data: bytes, refusals: list[str], degradations: list[str]):
        self.data = data
        self.refusals = refusals
        self.degradations = degradations
        self.sector_size = 512
        self.mini_sector_size = 64
        self.fat: list[int] = []
        self.mini_fat: list[int] = []
        self.mini_stream = b""
        self.entries: list[dict] = []
        self.total_read = 0
        if len(data) < 512:
            raise CfbfError("shorter than the CFBF header")
        if not is_cfbf_bytes(data[:8]):
            raise CfbfError("not a CFBF image")
        self._parse_header()
        self._load_fat()
        self._load_directory()
        self._load_mini_fat()
        self._load_mini_stream()

    # -- low-level ---------------------------------------------------------

    def _parse_header(self) -> None:
        data = self.data
        self.major_version, self.minor_version = struct.unpack("<HH", data[26:30])
        sector_shift, mini_shift = struct.unpack("<HH", data[30:34])
        if sector_shift == 0 or sector_shift > 20:
            self.refusals.append("sector_shift_invalid")
            raise CfbfError("invalid sector shift")
        self.sector_size = 1 << sector_shift
        self.mini_sector_size = 1 << mini_shift if 0 < mini_shift <= 12 else 64
        # MS-CFB: the header occupies one whole sector — 512 bytes for the
        # common version 3, 4,096 for version 4 databases. Sector 0 begins
        # at the end of the header.
        self.header_size = self.sector_size if self.major_version >= 4 else 512
        (
            self.n_dir_sectors,
            self.n_fat_sectors,
            self.first_dir_sector,
            self.transaction_sig,
            self.mini_cutoff,
            self.first_mini_fat_sector,
            self.n_mini_fat_sectors,
            self.first_difat_sector,
            self.n_difat_sectors,
        ) = struct.unpack("<IIIIIIIII", data[40:76])
        self.difat = list(struct.unpack("<109I", data[76:512]))
        self.sector_count = max(0, (len(data) - self.header_size) // self.sector_size)
        self.clsid = data[8:24].hex()

    def sector(self, index: int) -> bytes:
        """One sector's bytes, range-checked against the file size."""
        start = self.header_size + index * self.sector_size
        chunk = self.data[start : start + self.sector_size]
        if len(chunk) < self.sector_size:
            # A truncated final sector is readable; a sector wholly past the
            # end is a broken chain.
            if not chunk:
                return b""
        return chunk

    def _load_fat(self) -> None:
        entries_per_sector = self.sector_size // 4
        fat_sector_ids = [s for s in self.difat if s < DIFSECT]
        # Chained DIFAT sectors extend the list past the header's 109.
        seen = set()
        difat_sector = self.first_difat_sector
        while difat_sector not in (ENDOFCHAIN, FREESECT) and difat_sector not in seen:
            seen.add(difat_sector)
            raw = self.sector(difat_sector)
            if len(raw) < self.sector_size:
                self.degradations.append("difat_sector_out_of_range")
                break
            values = struct.unpack(f"<{entries_per_sector}I", raw)
            fat_sector_ids += [s for s in values[:-1] if s < DIFSECT]
            difat_sector = values[-1]
        if len(seen) > MAX_DIRECTORY_ENTRIES:
            self.degradations.append("difat_chain_loop")
            return
        for fat_sector in fat_sector_ids[:MAX_DIRECTORY_ENTRIES]:
            if fat_sector >= self.sector_count and self.sector(fat_sector) == b"":
                self.degradations.append("sector_out_of_range")
                continue
            raw = self.sector(fat_sector)
            if len(raw) == self.sector_size:
                self.fat += struct.unpack(f"<{entries_per_sector}I", raw)

    def _chain(self, start: int, *, mini: bool = False) -> tuple[list[int], bool]:
        """Walk one FAT chain: sector ids and whether the walk completed.

        A loop, an out-of-range sector or a FREESECT terminator records a
        named degradation (a malformed chain is a finding, not a swallow)
        and returns what it safely saw; the caller decides how much of the
        stream that leaves readable.
        """
        fat = self.mini_fat if mini else self.fat
        limit_name = "minifat_chain_loop" if mini else "fat_chain_loop"
        chain: list[int] = []
        seen: set[int] = set()
        index = start
        completed = False
        bound = min(len(fat) + 1, MAX_DIRECTORY_ENTRIES * 64)
        for _ in range(bound):
            if index == ENDOFCHAIN:
                completed = True
                break
            if index == FREESECT:
                self.degradations.append("chain_terminated_early")
                break
            if index in seen:
                self.degradations.append(limit_name)
                break
            if index >= len(fat):
                self.degradations.append("sector_out_of_range")
                break
            seen.add(index)
            chain.append(index)
            index = fat[index]
        else:
            self.degradations.append(limit_name)
        return chain, completed

    def _read_chain(self, start: int, size: int, cap: int) -> bytes:
        """Read one regular (FAT) chain's stream, bounded by ``cap``."""
        if size > cap:
            self.refusals.append("stream_size_exceeds_cap")
            return b""
        if self.total_read + size > MAX_TOTAL_STREAM_READ:
            self.refusals.append("total_stream_read_exceeds_cap")
            return b""
        chain, completed = self._chain(start)
        if not completed:
            self.degradations.append("stream_chain_broken")
        out = []
        remaining = size
        step = self.sector_size
        for index in chain:
            if remaining <= 0:
                break
            chunk = self.sector(index)[: min(step, remaining)]
            out.append(chunk)
            remaining -= len(chunk)
        data = b"".join(out)
        self.total_read += len(data)
        return data

    def _load_mini_fat(self) -> None:
        entries_per_sector = self.sector_size // 4
        if not self.n_mini_fat_sectors:
            return
        sectors, _ = self._chain(self.first_mini_fat_sector)
        for index in sectors[: self.n_mini_fat_sectors + 1]:
            raw = self.sector(index)
            if len(raw) == self.sector_size:
                self.mini_fat += struct.unpack(f"<{entries_per_sector}I", raw)

    def _load_mini_stream(self) -> None:
        """The root entry's own stream holds every mini stream's bytes."""
        root = next((e for e in self.entries if e["type"] == ENTRY_ROOT), None)
        if root is None or root["size"] == 0:
            return
        if root["size"] > MAX_MINI_STREAM_READ:
            self.refusals.append("mini_stream_exceeds_cap")
            return
        chain, _ = self._chain(root["start"])
        out = []
        remaining = root["size"]
        for index in chain:
            if remaining <= 0:
                break
            chunk = self.sector(index)[: min(self.sector_size, remaining)]
            out.append(chunk)
            remaining -= len(chunk)
        self.mini_stream = b"".join(out)

    def read_mini_chain(self, start: int, size: int, cap: int) -> bytes:
        """Read one mini stream's bytes out of the root mini stream."""
        if size > cap:
            self.refusals.append("stream_size_exceeds_cap")
            return b""
        if self.total_read + size > MAX_TOTAL_STREAM_READ:
            self.refusals.append("total_stream_read_exceeds_cap")
            return b""
        chain, completed = self._chain(start, mini=True)
        if not completed:
            self.degradations.append("stream_chain_broken")
        out = []
        remaining = size
        for index in chain:
            if remaining <= 0:
                break
            begin = index * self.mini_sector_size
            chunk = self.mini_stream[begin : begin + self.mini_sector_size][: min(self.mini_sector_size, remaining)]
            out.append(chunk)
            remaining -= len(chunk)
        data = b"".join(out)
        self.total_read += len(data)
        return data

    # -- directory ---------------------------------------------------------

    def _load_directory(self) -> None:
        chain, _ = self._chain(self.first_dir_sector)
        raw = b"".join(self.sector(index) for index in chain)
        count = min(len(raw) // 128, MAX_DIRECTORY_ENTRIES)
        if len(raw) // 128 > MAX_DIRECTORY_ENTRIES:
            self.refusals.append("directory_entry_count_exceeds_cap")
        for position in range(count):
            entry = raw[position * 128 : (position + 1) * 128]
            name_len = struct.unpack("<H", entry[64:66])[0]
            name = ""
            if 2 <= name_len <= 64:
                name = entry[: name_len - 2].decode("utf-16-le", "replace")
            entry_type = entry[66]
            left, right, child = struct.unpack("<III", entry[68:80])
            start, size = struct.unpack("<II", entry[116:124])
            self.entries.append(
                {
                    "index": position,
                    "name": name,
                    "type": entry_type,
                    "left": left,
                    "right": right,
                    "child": child,
                    "start": start,
                    "size": size,
                }
            )

    def tree(self) -> list[dict]:
        """Flatten the directory tree with full storage paths.

        Walks the red-black tree from the root's child; a malformed tree
        (loop, out-of-range sibling) degrades to a linear listing of the
        valid entries with their indices as pseudo-paths, named as such.
        """
        root = next((e for e in self.entries if e["type"] == ENTRY_ROOT), None)
        out: list[dict] = []
        visited: set[int] = set()

        def walk(index: int, path: str, depth: int) -> None:
            if index in (NOSTREAM, ENDOFCHAIN, FREESECT) or len(out) >= MAX_STREAMS_LISTED:
                return
            if index in visited or index >= len(self.entries) or depth > MAX_TREE_DEPTH:
                self.degradations.append("directory_tree_loop")
                return
            visited.add(index)
            entry = self.entries[index]
            if entry["type"] == ENTRY_UNUSED:
                return
            name = entry["name"]
            child_path = f"{path}/{name}" if path else name
            walk(entry["left"], path, depth + 1)
            out.append(
                {
                    "name": name,
                    "path": child_path,
                    "type": {1: "storage", 2: "stream", 5: "root"}.get(entry["type"], "other"),
                    "size": entry["size"],
                    "index": index,
                }
            )
            walk(entry["right"], path, depth + 1)
            if entry["type"] in (ENTRY_ROOT, ENTRY_STORAGE):
                walk(entry["child"], child_path, depth + 1)

        if root is not None:
            walk(root["child"], "", 0)
        if not out and any(e["type"] in (ENTRY_STREAM, ENTRY_STORAGE) for e in self.entries):
            # Tree walk saw nothing: fall back to a linear listing rather
            # than presenting an empty storage (rule 32).
            self.degradations.append("directory_tree_unwalkable")
            for entry in self.entries:
                if entry["type"] in (ENTRY_STREAM, ENTRY_STORAGE) and len(out) < MAX_STREAMS_LISTED:
                    out.append(
                        {
                            "name": entry["name"],
                            "path": f"@{entry['index']}",
                            "type": "stream" if entry["type"] == ENTRY_STREAM else "storage",
                            "size": entry["size"],
                            "index": entry["index"],
                        }
                    )
        return out

    def read_entry(self, entry: dict, cap: int = MAX_STREAM_READ) -> bytes:
        """One stream's bytes (mini or regular), bounded by ``cap``."""
        if entry.get("type") != "stream":
            return b""
        raw_entry = self.entries[entry["index"]]
        if raw_entry["size"] < self.mini_cutoff:
            return self.read_mini_chain(raw_entry["start"], raw_entry["size"], cap)
        return self._read_chain(raw_entry["start"], raw_entry["size"], cap)

    def find(self, path: str) -> dict | None:
        """The tree entry whose path matches exactly (case-insensitive)."""
        lowered = path.lower()
        for entry in self.tree():
            if entry["path"].lower() == lowered:
                return entry
        return None


def parse_cfbf(data: bytes) -> dict:
    """Parse one CFBF image into blint's storage facts block.

    Returns a dict with ``parse_status`` (``parsed``/``partial``/``failed``),
    the sector and storage counts, the flattened stream listing and every
    named refusal/degradation. Structure facts survive partial reads: a
    broken chain names itself and the tree still lists what was walked.
    """
    block: dict = {
        "parse_status": "parsed",
        "sector_size": None,
        "sector_count": 0,
        "stream_count": 0,
        "storage_count": 0,
        "clsid": None,
        "entries": [],
        "refusals": [],
        "degradations": [],
    }
    refusals = block["refusals"]
    degradations = block["degradations"]
    try:
        reader = CfbfReader(data, refusals, degradations)
    except CfbfError:
        block["parse_status"] = "failed"
        return block
    block["sector_size"] = reader.sector_size
    block["sector_count"] = reader.sector_count
    block["clsid"] = reader.clsid
    tree = reader.tree()
    for entry in tree:
        if entry["type"] == "stream":
            block["stream_count"] += 1
        elif entry["type"] == "storage":
            block["storage_count"] += 1
    block["entries"] = [
        {"name": e["name"], "path": e["path"], "type": e["type"], "size": e["size"]}
        for e in tree
    ]
    if degradations:
        block["parse_status"] = "partial"
    return block


def iter_summary_information(reader: CfbfReader) -> dict:
    """Read the ``\\x05SummaryInformation`` property set (MSI and Office).

    The property-set frame: byte order, version, system id, CLSID, count,
    then per-property (id, offset) with typed values. Only the string,
    integer and filetime properties blint reports are decoded; anything
    else is skipped rather than guessed.
    """
    import contextlib
    import datetime

    entry = reader.find("\x05SummaryInformation")
    if entry is None:
        return {}
    data = reader.read_entry(entry)
    if len(data) < 48:
        return {}
    with contextlib.suppress(struct.error, IndexError):
        # PropertySetStream: byteOrder(2) version(2) sysVersion(4) clsid(16)
        # numSets(4) fmtid(16) offset(4) size(4); the section starts at the
        # offset, and property offsets are relative to the section start.
        (section_offset,) = struct.unpack("<I", data[44:48])
        # Empirically (7z-x64.msi and Office documents): the offset names
        # the section, the section carries its size (4) then its property
        # count (4), then (id, offset) entries whose offsets are relative
        # to the section start.
        (count,) = struct.unpack("<I", data[section_offset + 4 : section_offset + 8])
        properties: dict = {}
        for index in range(min(count, 64)):
            base = section_offset + 8 + index * 8
            prop_id, offset = struct.unpack("<II", data[base : base + 8])
            offset += section_offset
            if offset + 4 > len(data):
                continue
            (value_type,) = struct.unpack("<H", data[offset : offset + 2])
            value: object
            if value_type in (2,):  # i2
                (value,) = struct.unpack("<h", data[offset + 4 : offset + 6])
            elif value_type in (3, 0x13):  # i4 / ui4
                (value,) = struct.unpack("<i" if value_type == 3 else "<I", data[offset + 4 : offset + 8])
            elif value_type == 0x1E:  # lpstr
                (length,) = struct.unpack("<I", data[offset + 4 : offset + 8])
                raw = data[offset + 8 : offset + 8 + max(0, length - 1)]
                value = raw.decode("latin-1", "replace")
            elif value_type == 0x40:  # filetime
                (filetime,) = struct.unpack("<Q", data[offset + 4 : offset + 12])
                value = (
                    datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=filetime // 10)
                ).isoformat() if filetime else None
            else:
                continue
            if value is not None:
                properties[prop_id] = value
        names = {
            2: "title",
            3: "subject",
            4: "author",
            5: "keywords",
            6: "comments",
            7: "template",
            8: "last_author",
            9: "revision_number",
            12: "create_time",
            13: "last_saved_time",
            15: "word_count",
            18: "application_name",
            19: "security",
        }
        return {names[prop_id]: value for prop_id, value in properties.items() if prop_id in names}
    return {}
