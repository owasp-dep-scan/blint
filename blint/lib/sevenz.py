"""7z container reader for 7z-SFX payloads (W4.3).

A 7z-SFX installer is a small PE stub followed by a whole 7z archive, so
"the payload is documented and stable" means reading 7z: the 32-byte
signature header (magic, version, start-header CRC, next-header
offset/size/CRC — all verified against the archive bytes), then the next
header — usually a ``kEncodedHeader`` whose real directory is itself LZMA-
compressed, which is why a stdlib-only reader must decode LZMA1/LZMA2
(``lzma`` module, raw format) to list members at all.

Only the directory is decompressed on the parse path. Member extraction
(:func:`extract_members`) decodes pack streams per folder; coders blint
cannot decode (BCJ2, PPMd, encrypted 7zAES) refuse by name with the method
named, and the folder's members are listed as refused rather than silently
absent (rule 32).

Bounds (ground rules 30/33), measured on the corpus 7z-SFX installers
(7-Zip 25.01, ~1.6 MB, 50-100 members): 16,384 members (cap), 512 MiB
total unpacked (cap), 256 MiB per member (cap), 64 MiB header blob (cap),
256 MiB per pack stream decode (cap). Hostile fixtures exceed each cap.

Reference: the format description in the LZMA SDK (7zFormat.txt); verified
against real archives created and listed by 7-Zip on the ground-truth VM.
"""

# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
# SPDX-License-Identifier: Apache-2.0

import lzma
import struct
import zlib

SEVENZ_MAGIC = b"7z\xbc\xaf\x27\x1c"

# Property IDs (LZMA SDK 7zFormat.txt).
K_END = 0x00
K_HEADER = 0x01
K_ARCHIVE_PROPERTIES = 0x02
K_ADDITIONAL_STREAMS = 0x03
K_MAIN_STREAMS = 0x04
K_FILES_INFO = 0x05
K_PACK_INFO = 0x06
K_UNPACK_INFO = 0x07
K_SUBSTREAMS_INFO = 0x08
K_SIZE = 0x09
K_CRC = 0x0A
K_FOLDER = 0x0B
K_CODERS_UNPACK_SIZE = 0x0C
K_NUM_UNPACK_STREAM = 0x0D
K_EMPTY_STREAM = 0x0E
K_EMPTY_FILE = 0x0F
K_NAME = 0x11
K_MTIME = 0x14
K_WIN_ATTRIBUTES = 0x15
K_DUMMY = 0x19
K_ENCODED_HEADER = 0x17

# Coder IDs.
CODER_COPY = 0x00
CODER_LZMA2 = 0x21
CODER_LZMA1 = 0x030101
CODER_BCJ2 = 0x0303011B
CODER_PPMD = 0x030401
CODER_AES256 = 0x06F10701
CODER_BCJ_X86 = 0x03030103

# Measured caps — see the module docstring.
MAX_MEMBERS = 16384
MAX_TOTAL_UNPACKED = 512 * 1024 * 1024
MAX_MEMBER_SIZE = 256 * 1024 * 1024
MAX_HEADER_BLOB = 64 * 1024 * 1024
MAX_PACK_STREAM_DECODE = 256 * 1024 * 1024


class SevenZError(ValueError):
    """The bytes are not a 7z archive or the header is unusable."""


def _read_number(data: bytes, pos: int) -> tuple[int, int]:
    """7z variable-length number: high bits flag extra low-order bytes."""
    first = data[pos]
    pos += 1
    mask = 0x80
    value = 0
    for i in range(7):
        if first & mask:
            value |= (data[pos] if pos < len(data) else 0) << (8 * i)
            pos += 1
            mask >>= 1
        else:
            value |= (first & (mask - 1)) << (8 * i)
            break
    return value, pos


def _bitvector(data: bytes, pos: int, count: int) -> list[bool]:
    bits = []
    byte = 0
    for index in range(count):
        if index % 8 == 0:
            byte = data[pos] if pos < len(data) else 0
            pos += 1
        bits.append(bool(byte & (1 << (index % 8))))
    return bits


def _lzma1_filters(props: bytes) -> dict:
    dict_size = struct.unpack("<I", props[1:5])[0] if len(props) >= 5 else 1 << 24
    d = props[0] if props else 0x5D
    lc = d % 9
    d //= 9
    lp = d % 5
    pb = d // 5
    return {"id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": lc, "lp": lp, "pb": pb}


def find_archive_candidates(data: bytes) -> list[int]:
    """Every 7z signature position in a blob (an SFX stub may embed false
    positives, and only the start-header CRC picks the real one)."""
    positions = []
    start = 0
    while True:
        pos = data.find(SEVENZ_MAGIC, start)
        if pos < 0:
            break
        positions.append(pos)
        start = pos + 1
        if len(positions) >= 64:
            break
    return positions


class SevenZipArchive:
    """Bounded reader over one in-memory 7z image."""

    def __init__(self, data: bytes, base_offset: int, refusals: list[str], degradations: list[str]):
        self.data = data
        self.base = base_offset
        self.refusals = refusals
        self.degradations = degradations
        self.version = None
        self.members: list[dict] = []
        self.folders: list[dict] = []
        self.pack_positions: list[int] = []
        self.pack_sizes: list[int] = []
        self.substream_sizes: list[list[int]] = []
        self._parse_signature_header()
        self._parse_next_header()

    # -- header level ------------------------------------------------------

    def _parse_signature_header(self) -> None:
        start = self.base
        data = self.data
        if data[start : start + 6] != SEVENZ_MAGIC or len(data) < start + 32:
            raise SevenZError("not a 7z archive")
        self.version = f"{data[start + 6]}.{data[start + 7]}"
        (next_off, next_size) = struct.unpack("<QQ", data[start + 12 : start + 28])
        (next_crc,) = struct.unpack("<I", data[start + 28 : start + 32])
        blob = data[start + 32 + next_off : start + 32 + next_off + next_size]
        if len(blob) != next_size:
            self.refusals.append("archive_truncated")
            raise SevenZError("start header points past the file")
        if zlib.crc32(blob) & 0xFFFFFFFF != next_crc:
            self.refusals.append("start_header_crc_mismatch")
            raise SevenZError("start header CRC mismatch")
        self.next_header_blob = blob

    def _parse_next_header(self) -> None:
        blob = self.next_header_blob
        if not blob:
            raise SevenZError("empty next header")
        if blob[0] == K_ENCODED_HEADER_PLACEHOLDER:
            pass
        if blob[0] == K_ENCODED_HEADER:
            streams, _pos = self._parse_streams_info(blob, 1, len(blob))
            folder0 = streams["folders"][0] if streams["folders"] else None
            if folder0 is None:
                raise SevenZError("encoded header with no folder")
            if folder0["coder_id"] not in (CODER_LZMA1, CODER_LZMA2, CODER_COPY):
                self.refusals.append("header_coder_unsupported")
                raise SevenZError(f"encoded header coder {hex(folder0['coder_id'])} unsupported")
            header_pack_size = self.pack_sizes[0] if self.pack_sizes else 0
            if header_pack_size > MAX_HEADER_BLOB:
                self.refusals.append("header_exceeds_cap")
                raise SevenZError("encoded header exceeds the cap")
            decompressed = self._decode_folder(folder0, self.pack_positions[0], pack_size=header_pack_size)
            self._parse_real_header(decompressed)
        elif blob[0] == K_HEADER:
            self._parse_real_header(blob[1:])
        else:
            raise SevenZError("unrecognised next header type")

    # -- property walks ----------------------------------------------------

    def _parse_streams_info(self, data: bytes, pos: int, end: int) -> tuple[dict, int]:
        """kMainStreamsInfo / kEncodedHeader body: PackInfo, UnpackInfo,
        SubStreamsInfo (LZMA SDK 7zFormat.txt grammar). Returns the result
        and the position after the streams info (its kEnd consumed)."""
        folders: list[dict] = []
        pack_pos = 0
        pack_sizes: list[int] = []
        substream_counts: list[int] | None = None
        substream_sizes: list[list[int]] | None = None
        while pos < end:
            prop = data[pos]
            pos += 1
            if prop == K_END:
                break
            if prop == K_PACK_INFO:
                pack_pos, pos = _read_number(data, pos)
                num_pack, pos = _read_number(data, pos)
                while pos < end and data[pos] == K_SIZE:
                    pos += 1
                    for _ in range(num_pack):
                        size, pos = _read_number(data, pos)
                        pack_sizes.append(size)
                pos = self._skip_optional_crc(data, pos)
                if pos < end and data[pos] == K_END:
                    pos += 1
            elif prop == K_UNPACK_INFO:
                if data[pos] != K_FOLDER:
                    break
                pos += 1
                num_folders, pos = _read_number(data, pos)
                pos += 1  # external byte (0 in files)
                for _ in range(min(num_folders, 1 << 20)):
                    num_coders, pos = _read_number(data, pos)
                    coder_id = None
                    props = b""
                    num_out = 1
                    for _coder in range(num_coders):
                        flags = data[pos]
                        pos += 1
                        id_size = flags & 0x0F
                        is_complex = bool(flags & 0x10)
                        has_attrs = bool(flags & 0x20)
                        coder_id = int.from_bytes(data[pos : pos + id_size], "big")
                        pos += id_size
                        if is_complex:
                            _total_in, pos = _read_number(data, pos)
                            num_out, pos = _read_number(data, pos)
                            for _out in range(num_out - 1):
                                _main_index, pos = _read_number(data, pos)
                        if has_attrs:
                            prop_size, pos = _read_number(data, pos)
                            props = data[pos : pos + prop_size]
                            pos += prop_size
                    folders.append({"coder_id": coder_id, "props": props, "num_out": num_out})
                # ONE kCodersUnpackSize marker covers every folder's output
                # streams, folders in order.
                if pos < end and data[pos] == K_CODERS_UNPACK_SIZE:
                    pos += 1
                    for folder in folders:
                        for out_index in range(folder["num_out"]):
                            size, pos = _read_number(data, pos)
                            if out_index == folder["num_out"] - 1:
                                folder["unpack_size"] = size
                else:
                    self.degradations.append("folder_unpack_sizes_unresolved")
                pos = self._skip_optional_crc(data, pos)
                if pos < end and data[pos] == K_END:
                    pos += 1
            elif prop == K_SUBSTREAMS_INFO:
                counts = [1] * len(folders)
                while pos < end and data[pos] == K_NUM_UNPACK_STREAM:
                    pos += 1
                    counts = []
                    for _ in range(len(folders)):
                        count, pos = _read_number(data, pos)
                        counts.append(count)
                while pos < end and data[pos] == K_SIZE:
                    pos += 1
                    substream_sizes = []
                    for index, count in enumerate(counts):
                        folder_sizes = []
                        unpack = folders[index].get("unpack_size")
                        # Every substream size is stored except the last of
                        # each folder, which is derived from the folder's
                        # unpack size minus the stored ones.
                        stored = count - 1 if count > 1 else count
                        running = 0
                        for _sub in range(stored):
                            size, pos = _read_number(data, pos)
                            folder_sizes.append(size)
                            running += size
                        if count > 1 and unpack is not None:
                            folder_sizes.append(unpack - running)
                        elif count == 1:
                            folder_sizes.append(unpack if unpack is not None else 0)
                        substream_sizes.append(folder_sizes)
                pos = self._skip_optional_crc(
                    data, pos, total=sum(len(s) for s in (substream_sizes or [[0]] * len(counts)))
                )
                if pos < end and data[pos] == K_END:
                    pos += 1
                substream_counts = counts
            elif prop == K_DUMMY:
                _size, pos = _read_number(data, pos)
                continue
            else:
                # Unknown property: leave the byte for the caller — at the
                # real-header level it is kFilesInfo, which _parse_real_
                # header must see.
                pos -= 1
                break
        self.pack_positions = [pack_pos]
        self.pack_sizes = pack_sizes
        self.folders = folders
        if substream_sizes is None:
            substream_sizes = [
                [f["unpack_size"]] if f.get("unpack_size") is not None else [] for f in folders
            ]
        self.substream_sizes = substream_sizes
        return {"folders": folders, "counts": substream_counts or [1] * len(folders)}, pos

    def _skip_optional_crc(self, data: bytes, pos: int, total: int | None = None) -> int:
        if pos >= len(data) or data[pos] != K_CRC:
            return pos
        pos += 1
        if total is None:
            # Unpack-info CRC: the count is a number after the marker.
            total, pos = _read_number(data, pos)
        # allDefined: a single 1 byte means every entry has a digest;
        # a 0 byte means a bitvector of defined-flags follows.
        all_defined = data[pos]
        pos += 1
        if all_defined:
            return pos + 4 * total
        defined = _bitvector(data, pos, total)
        pos += (total + 7) // 8
        for is_defined in defined:
            if is_defined:
                pos += 4
        return pos

    def _skip_crc_block(self, data: bytes, pos: int, counts: list[int]) -> int:
        total = sum(counts)
        defined = _bitvector(data, pos, total)
        pos += (total + 7) // 8
        for is_defined in defined:
            if is_defined:
                pos += 4
        return pos

    def _parse_real_header(self, data: bytes) -> None:
        """kHeader: FilesInfo with names, empty-stream bits, sizes. The
        decoded blob begins with the kHeader byte itself."""
        pos = 1 if data and data[0] == K_HEADER else 0
        end = len(data)
        empty_streams: list[bool] = []
        empty_files: list[bool] = []
        names: list[str] = []
        while pos < end:
            prop = data[pos]
            pos += 1
            if prop == K_END:
                # Stray kEnd (e.g. the MainStreamsInfo terminator already
                # consumed inside its own walk) — keep scanning for
                # kFilesInfo, which may legally follow.
                continue
            if prop == K_FILES_INFO:
                num_files, pos = _read_number(data, pos)
                if num_files > MAX_MEMBERS:
                    self.refusals.append("member_count_exceeds_cap")
                    num_files = MAX_MEMBERS
                while pos < end:
                    prop_type = data[pos]
                    pos += 1
                    if prop_type == K_END:
                        break
                    # Property size is a variable-length number (verified
                    # against real archives: kDummy 2, kName 41, kMTime 18).
                    size, pos = _read_number(data, pos)
                    prop_end = pos + size
                    if prop_type == K_EMPTY_STREAM:
                        empty_streams = _bitvector(data, pos, num_files)
                    elif prop_type == K_EMPTY_FILE:
                        empty_files = _bitvector(data, pos, sum(empty_streams))
                    elif prop_type == K_NAME:
                        pos += 1  # external byte
                        raw_names = data[pos:prop_end].decode("utf-16-le", "replace")
                        names = [n for n in raw_names.split("\x00") if n]
                    pos = prop_end
            elif prop == K_MAIN_STREAMS:
                streams, pos = self._parse_streams_info(data, pos, end)
                self.folders = streams["folders"]
                self._assign_member_sizes()
            elif prop == K_DUMMY:
                continue
            else:
                break
        # Names line up with non-empty-stream entries in order; empty-stream
        # entries with the empty-file bit are zero-byte members.
        substream_index = 0
        member_index = 0
        empty_seen = 0
        for index in range(max(len(names), len(empty_streams) or len(names))):
            if index >= len(empty_streams) or not empty_streams[index]:
                size = 0
                folder_sizes = None
                for sizes in self.substream_sizes:
                    if substream_index < len(sizes):
                        size = sizes[substream_index]
                        break
                if self.substream_sizes and self.substream_sizes[0]:
                    folder_sizes = self.substream_sizes[0]
                if folder_sizes and substream_index < len(folder_sizes):
                    size = folder_sizes[substream_index]
                    substream_index += 1
                name = names[member_index] if member_index < len(names) else f"member_{index}"
                member_index += 1
                self.members.append({"name": name, "size": size})
            else:
                empty_seen += 1
                is_file = empty_files[empty_seen - 1] if empty_seen - 1 < len(empty_files) else True
                name = names[member_index] if member_index < len(names) else f"member_{index}"
                member_index += 1
                if is_file:
                    self.members.append({"name": name, "size": 0})
        if len(names) > len(self.members):
            for name in names[len(self.members):]:
                self.members.append({"name": name, "size": None, "unresolved": True})

    def _assign_member_sizes(self) -> None:
        if not self.substream_sizes and self.folders:
            self.substream_sizes = [
                [folder["unpack_size"] or 0] if folder["unpack_size"] is not None else []
                for folder in self.folders
            ]

    # -- decode ------------------------------------------------------------

    def _decode_folder(
        self, folder: dict, pack_offset: int, pack_size: int | None = None, cap: int = MAX_PACK_STREAM_DECODE
    ) -> bytes:
        """Decode one folder's pack stream: LZMA1/LZMA2/copy only."""
        method_name = {
            CODER_LZMA1: "lzma",
            CODER_LZMA2: "lzma2",
            CODER_COPY: "copy",
        }.get(folder["coder_id"])
        if method_name is None:
            self.refusals.append("member_compression_unsupported")
            return b""
        start = self.base + 32 + pack_offset
        blob = self.data[start : start + (pack_size or folder.get("pack_size") or len(self.data))]
        if not blob:
            self.refusals.append("archive_truncated")
            return b""
        if len(blob) > cap:
            self.refusals.append("member_size_exceeds_cap")
            return b""
        if method_name == "copy":
            return blob
        expected = folder.get("unpack_size")
        if method_name == "lzma":
            filters = [_lzma1_filters(folder["props"])]
            decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
        else:
            if len(folder["props"]) >= 2:
                dict_size = (folder["props"][0] | 1) << (folder["props"][1] + 11)
            else:
                dict_size = 1 << 24
            filters = [{"id": lzma.FILTER_LZMA2, "dict_size": dict_size}]
            decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
        out = decompressor.decompress(blob, max_length=(expected or cap) + 1)
        if expected is not None and len(out) > expected:
            out = out[:expected]
        return out

    def extract(self, name: str, dest_dir: str, *, member_cap: int = MAX_MEMBER_SIZE) -> str | None:
        """Extract one member by name into ``dest_dir``; None on refusal.

        Members in folders blint cannot decode refuse by name before any
        decode; sizes are enforced against both the declared unpack size
        and the cap.
        """
        member = next((m for m in self.members if m["name"] == name), None)
        if member is None:
            return None
        size = member.get("size") or 0
        if size > member_cap or size > MAX_MEMBER_SIZE:
            self.refusals.append("member_size_exceeds_cap")
            return None
        if not self.folders:
            self.refusals.append("member_unreadable")
            return None
        folder = self.folders[0]
        if folder["coder_id"] not in (CODER_LZMA1, CODER_LZMA2, CODER_COPY):
            self.refusals.append("member_compression_unsupported")
            return None
        decoded = self._decode_folder(
            folder,
            self.pack_positions[0] if self.pack_positions else 0,
            pack_size=self.pack_sizes[0] if self.pack_sizes else None,
        )
        if not decoded:
            return None
        # The solid folder holds every member sequentially in name order.
        offset = 0
        for entry in self.members:
            entry_size = entry.get("size") or 0
            if entry["name"] == name:
                chunk = decoded[offset : offset + entry_size]
                if len(chunk) < entry_size:
                    self.refusals.append("archive_truncated")
                    return None
                import os

                dest = os.path.join(dest_dir, *name.replace("\\\\", "/").split("/"))
                parent = os.path.dirname(dest)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                with open(dest, "wb") as handle:
                    handle.write(chunk)
                return dest
            offset += entry_size
        return None


K_ENCODED_HEADER_PLACEHOLDER = 0x17


def _build_archive(data: bytes, refusals: list[str], degradations: list[str]):
    """Fully-parsed archive over in-memory bytes (probes each signature)."""
    candidates = find_archive_candidates(data)
    for offset in candidates:
        probe = SevenZipArchive.__new__(SevenZipArchive)
        probe.data = data
        probe.base = offset
        probe.refusals = refusals
        probe.degradations = degradations
        probe.members = []
        probe.folders = []
        probe.pack_positions = []
        probe.pack_sizes = []
        probe.substream_sizes = []
        try:
            probe._parse_signature_header()
            probe._parse_next_header()
            return probe
        except SevenZError:
            continue
    return None


def extract_sevenz_members(
    data: bytes, dest_dir: str, refusals: list[str]
) -> dict[str, str]:
    """Extract every member the coders allow into ``dest_dir``.

    Solid folders decode once (bounded) and members are sliced from the
    decoded bytes in name order; folders whose coder blint cannot decode
    (BCJ2, PPMd, encrypted) refuse by name for their members. Returns
    member name -> extracted path for the clean extractions; the caller
    owns ``dest_dir`` cleanup.
    """
    extracted: dict[str, str] = {}
    archive = _build_archive(data, refusals, [])
    if archive is None:
        refusals.append("archive_unreadable")
        return extracted
    decoded_folders = []
    for index, folder in enumerate(archive.folders):
        if folder.get("coder_id") not in (CODER_LZMA1, CODER_LZMA2, CODER_COPY):
            refusals.append("member_compression_unsupported")
            decoded_folders.append(None)
            continue
        decoded_folders.append(
            archive._decode_folder(
                folder,
                archive.pack_positions[0] if archive.pack_positions else 0,
                pack_size=archive.pack_sizes[index] if index < len(archive.pack_sizes) else None,
            )
        )
    # Members map to folders through the substream lists, in order.
    substream_cursor = 0
    decoded_cursor = 0
    for member in archive.members:
        if decoded_cursor >= len(decoded_folders):
            break
        blob = decoded_folders[decoded_cursor]
        sizes = archive.substream_sizes[substream_cursor] if substream_cursor < len(archive.substream_sizes) else []
        if not sizes or member.get("size") is None:
            refusals.append("member_unresolved")
            continue
        if member["size"] > MAX_MEMBER_SIZE:
            refusals.append("member_size_exceeds_cap")
            continue
        if blob is None:
            refusals.append("member_compression_unsupported")
            continue
        offset = 0
        for entry in archive.members:
            if entry is member:
                break
            offset += entry.get("size") or 0
        chunk = blob[offset : offset + member["size"]]
        if len(chunk) < member["size"]:
            refusals.append("archive_truncated")
            continue
        import os

        name = member["name"].replace("\\", "/")
        dest = os.path.join(dest_dir, *name.split("/"))
        parent = os.path.dirname(dest)
        if parent:
            os.makedirs(parent, exist_ok=True)
        try:
            with open(dest, "wb") as handle:
                handle.write(chunk)
        except OSError:
            refusals.append("member_unreadable")
            continue
        extracted[member["name"]] = dest
    return extracted


def parse_sevenz_blob(data: bytes, refusals: list[str], degradations: list[str]) -> dict | None:
    """Parse the 7z archive embedded in ``data`` (usually an SFX overlay).

    Returns the facts block or None when no 7z signature is present. Only
    the (possibly compressed) directory is decoded here.
    """
    candidates = find_archive_candidates(data)
    if not candidates:
        return None
    block: dict = {
        "payload_offset": candidates[0],
        "version": None,
        "member_count": 0,
        "members": [],
        "total_unpacked": 0,
        "refusals": [],
        "degradations": [],
    }
    archive = None
    for offset in candidates:
        probe_refusals: list[str] = []
        probe = SevenZipArchive.__new__(SevenZipArchive)
        probe.data = data
        probe.base = offset
        probe.refusals = probe_refusals
        probe.degradations = degradations
        probe.members = []
        probe.folders = []
        probe.pack_positions = []
        probe.pack_sizes = []
        probe.substream_sizes = []
        try:
            probe._parse_signature_header()
            archive = probe
            block["payload_offset"] = offset
            refusals.extend(probe_refusals)
            break
        except SevenZError:
            continue
    if archive is None:
        degradations.append("header_unusable:no candidate passed the start-header CRC")
        return block
    try:
        archive._parse_next_header()
    except SevenZError as exc:
        degradations.append(f"header_unusable:{exc}")
        return block
    if archive.folders and any(
        folder.get("coder_id") not in (CODER_LZMA1, CODER_LZMA2, CODER_COPY)
        for folder in archive.folders
    ):
        refusals.append("member_compression_unsupported")
    block["version"] = archive.version
    block["members"] = archive.members[:MAX_MEMBERS]
    block["member_count"] = len(archive.members)
    block["total_unpacked"] = sum(m["size"] or 0 for m in archive.members if m["size"])
    return block
