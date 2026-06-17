"""
Dalvik bytecode disassembler.

LIEF parses the structure of a dex file (classes, methods, fields) and exposes a
method's raw Dalvik bytecode via ``lief.DEX.Method.bytecode``, but it does not
decode that bytecode into instructions. This module decodes the raw bytecode
against the canonical Dalvik opcode/format table so the instruction stream of a
method can be inspected for analysis.

The opcode table and instruction formats follow the public Dalvik specification
(https://source.android.com/docs/core/runtime/dalvik-bytecode and
.../instruction-formats). Decoding is purely structural: it yields the opcode,
mnemonic, register operands and any literal / branch / constant-pool index for
each instruction. Resolving pool indices to names is left to the caller, which
has the dex string/type/method/field tables.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Union

# Map of opcode byte -> (mnemonic, format id). Unused opcodes are intentionally
# omitted and handled as single-code-unit unknowns so the instruction stream
# stays aligned even when an unexpected byte is encountered.
OPCODES: dict[int, tuple[str, str]] = {
    0x00: ("nop", "10x"),
    0x01: ("move", "12x"),
    0x02: ("move/from16", "22x"),
    0x03: ("move/16", "32x"),
    0x04: ("move-wide", "12x"),
    0x05: ("move-wide/from16", "22x"),
    0x06: ("move-wide/16", "32x"),
    0x07: ("move-object", "12x"),
    0x08: ("move-object/from16", "22x"),
    0x09: ("move-object/16", "32x"),
    0x0A: ("move-result", "11x"),
    0x0B: ("move-result-wide", "11x"),
    0x0C: ("move-result-object", "11x"),
    0x0D: ("move-exception", "11x"),
    0x0E: ("return-void", "10x"),
    0x0F: ("return", "11x"),
    0x10: ("return-wide", "11x"),
    0x11: ("return-object", "11x"),
    0x12: ("const/4", "11n"),
    0x13: ("const/16", "21s"),
    0x14: ("const", "31i"),
    0x15: ("const/high16", "21h"),
    0x16: ("const-wide/16", "21s"),
    0x17: ("const-wide/32", "31i"),
    0x18: ("const-wide", "51l"),
    0x19: ("const-wide/high16", "21h"),
    0x1A: ("const-string", "21c"),
    0x1B: ("const-string/jumbo", "31c"),
    0x1C: ("const-class", "21c"),
    0x1D: ("monitor-enter", "11x"),
    0x1E: ("monitor-exit", "11x"),
    0x1F: ("check-cast", "21c"),
    0x20: ("instance-of", "22c"),
    0x21: ("array-length", "12x"),
    0x22: ("new-instance", "21c"),
    0x23: ("new-array", "22c"),
    0x24: ("filled-new-array", "35c"),
    0x25: ("filled-new-array/range", "3rc"),
    0x26: ("fill-array-data", "31t"),
    0x27: ("throw", "11x"),
    0x28: ("goto", "10t"),
    0x29: ("goto/16", "20t"),
    0x2A: ("goto/32", "30t"),
    0x2B: ("packed-switch", "31t"),
    0x2C: ("sparse-switch", "31t"),
    0x2D: ("cmpl-float", "23x"),
    0x2E: ("cmpg-float", "23x"),
    0x2F: ("cmpl-double", "23x"),
    0x30: ("cmpg-double", "23x"),
    0x31: ("cmp-long", "23x"),
    0x32: ("if-eq", "22t"),
    0x33: ("if-ne", "22t"),
    0x34: ("if-lt", "22t"),
    0x35: ("if-ge", "22t"),
    0x36: ("if-gt", "22t"),
    0x37: ("if-le", "22t"),
    0x38: ("if-eqz", "21t"),
    0x39: ("if-nez", "21t"),
    0x3A: ("if-ltz", "21t"),
    0x3B: ("if-gez", "21t"),
    0x3C: ("if-gtz", "21t"),
    0x3D: ("if-lez", "21t"),
    0x44: ("aget", "23x"),
    0x45: ("aget-wide", "23x"),
    0x46: ("aget-object", "23x"),
    0x47: ("aget-boolean", "23x"),
    0x48: ("aget-byte", "23x"),
    0x49: ("aget-char", "23x"),
    0x4A: ("aget-short", "23x"),
    0x4B: ("aput", "23x"),
    0x4C: ("aput-wide", "23x"),
    0x4D: ("aput-object", "23x"),
    0x4E: ("aput-boolean", "23x"),
    0x4F: ("aput-byte", "23x"),
    0x50: ("aput-char", "23x"),
    0x51: ("aput-short", "23x"),
    0x52: ("iget", "22c"),
    0x53: ("iget-wide", "22c"),
    0x54: ("iget-object", "22c"),
    0x55: ("iget-boolean", "22c"),
    0x56: ("iget-byte", "22c"),
    0x57: ("iget-char", "22c"),
    0x58: ("iget-short", "22c"),
    0x59: ("iput", "22c"),
    0x5A: ("iput-wide", "22c"),
    0x5B: ("iput-object", "22c"),
    0x5C: ("iput-boolean", "22c"),
    0x5D: ("iput-byte", "22c"),
    0x5E: ("iput-char", "22c"),
    0x5F: ("iput-short", "22c"),
    0x60: ("sget", "21c"),
    0x61: ("sget-wide", "21c"),
    0x62: ("sget-object", "21c"),
    0x63: ("sget-boolean", "21c"),
    0x64: ("sget-byte", "21c"),
    0x65: ("sget-char", "21c"),
    0x66: ("sget-short", "21c"),
    0x67: ("sput", "21c"),
    0x68: ("sput-wide", "21c"),
    0x69: ("sput-object", "21c"),
    0x6A: ("sput-boolean", "21c"),
    0x6B: ("sput-byte", "21c"),
    0x6C: ("sput-char", "21c"),
    0x6D: ("sput-short", "21c"),
    0x6E: ("invoke-virtual", "35c"),
    0x6F: ("invoke-super", "35c"),
    0x70: ("invoke-direct", "35c"),
    0x71: ("invoke-static", "35c"),
    0x72: ("invoke-interface", "35c"),
    0x74: ("invoke-virtual/range", "3rc"),
    0x75: ("invoke-super/range", "3rc"),
    0x76: ("invoke-direct/range", "3rc"),
    0x77: ("invoke-static/range", "3rc"),
    0x78: ("invoke-interface/range", "3rc"),
    0x7B: ("neg-int", "12x"),
    0x7C: ("not-int", "12x"),
    0x7D: ("neg-long", "12x"),
    0x7E: ("not-long", "12x"),
    0x7F: ("neg-float", "12x"),
    0x80: ("neg-double", "12x"),
    0x81: ("int-to-long", "12x"),
    0x82: ("int-to-float", "12x"),
    0x83: ("int-to-double", "12x"),
    0x84: ("long-to-int", "12x"),
    0x85: ("long-to-float", "12x"),
    0x86: ("long-to-double", "12x"),
    0x87: ("float-to-int", "12x"),
    0x88: ("float-to-long", "12x"),
    0x89: ("float-to-double", "12x"),
    0x8A: ("double-to-int", "12x"),
    0x8B: ("double-to-long", "12x"),
    0x8C: ("double-to-float", "12x"),
    0x8D: ("int-to-byte", "12x"),
    0x8E: ("int-to-char", "12x"),
    0x8F: ("int-to-short", "12x"),
    0x90: ("add-int", "23x"),
    0x91: ("sub-int", "23x"),
    0x92: ("mul-int", "23x"),
    0x93: ("div-int", "23x"),
    0x94: ("rem-int", "23x"),
    0x95: ("and-int", "23x"),
    0x96: ("or-int", "23x"),
    0x97: ("xor-int", "23x"),
    0x98: ("shl-int", "23x"),
    0x99: ("shr-int", "23x"),
    0x9A: ("ushr-int", "23x"),
    0x9B: ("add-long", "23x"),
    0x9C: ("sub-long", "23x"),
    0x9D: ("mul-long", "23x"),
    0x9E: ("div-long", "23x"),
    0x9F: ("rem-long", "23x"),
    0xA0: ("and-long", "23x"),
    0xA1: ("or-long", "23x"),
    0xA2: ("xor-long", "23x"),
    0xA3: ("shl-long", "23x"),
    0xA4: ("shr-long", "23x"),
    0xA5: ("ushr-long", "23x"),
    0xA6: ("add-float", "23x"),
    0xA7: ("sub-float", "23x"),
    0xA8: ("mul-float", "23x"),
    0xA9: ("div-float", "23x"),
    0xAA: ("rem-float", "23x"),
    0xAB: ("add-double", "23x"),
    0xAC: ("sub-double", "23x"),
    0xAD: ("mul-double", "23x"),
    0xAE: ("div-double", "23x"),
    0xAF: ("rem-double", "23x"),
    0xB0: ("add-int/2addr", "12x"),
    0xB1: ("sub-int/2addr", "12x"),
    0xB2: ("mul-int/2addr", "12x"),
    0xB3: ("div-int/2addr", "12x"),
    0xB4: ("rem-int/2addr", "12x"),
    0xB5: ("and-int/2addr", "12x"),
    0xB6: ("or-int/2addr", "12x"),
    0xB7: ("xor-int/2addr", "12x"),
    0xB8: ("shl-int/2addr", "12x"),
    0xB9: ("shr-int/2addr", "12x"),
    0xBA: ("ushr-int/2addr", "12x"),
    0xBB: ("add-long/2addr", "12x"),
    0xBC: ("sub-long/2addr", "12x"),
    0xBD: ("mul-long/2addr", "12x"),
    0xBE: ("div-long/2addr", "12x"),
    0xBF: ("rem-long/2addr", "12x"),
    0xC0: ("and-long/2addr", "12x"),
    0xC1: ("or-long/2addr", "12x"),
    0xC2: ("xor-long/2addr", "12x"),
    0xC3: ("shl-long/2addr", "12x"),
    0xC4: ("shr-long/2addr", "12x"),
    0xC5: ("ushr-long/2addr", "12x"),
    0xC6: ("add-float/2addr", "12x"),
    0xC7: ("sub-float/2addr", "12x"),
    0xC8: ("mul-float/2addr", "12x"),
    0xC9: ("div-float/2addr", "12x"),
    0xCA: ("rem-float/2addr", "12x"),
    0xCB: ("add-double/2addr", "12x"),
    0xCC: ("sub-double/2addr", "12x"),
    0xCD: ("mul-double/2addr", "12x"),
    0xCE: ("div-double/2addr", "12x"),
    0xCF: ("rem-double/2addr", "12x"),
    0xD0: ("add-int/lit16", "22s"),
    0xD1: ("rsub-int", "22s"),
    0xD2: ("mul-int/lit16", "22s"),
    0xD3: ("div-int/lit16", "22s"),
    0xD4: ("rem-int/lit16", "22s"),
    0xD5: ("and-int/lit16", "22s"),
    0xD6: ("or-int/lit16", "22s"),
    0xD7: ("xor-int/lit16", "22s"),
    0xD8: ("add-int/lit8", "22b"),
    0xD9: ("rsub-int/lit8", "22b"),
    0xDA: ("mul-int/lit8", "22b"),
    0xDB: ("div-int/lit8", "22b"),
    0xDC: ("rem-int/lit8", "22b"),
    0xDD: ("and-int/lit8", "22b"),
    0xDE: ("or-int/lit8", "22b"),
    0xDF: ("xor-int/lit8", "22b"),
    0xE0: ("shl-int/lit8", "22b"),
    0xE1: ("shr-int/lit8", "22b"),
    0xE2: ("ushr-int/lit8", "22b"),
    0xFA: ("invoke-polymorphic", "45cc"),
    0xFB: ("invoke-polymorphic/range", "4rcc"),
    0xFC: ("invoke-custom", "35c"),
    0xFD: ("invoke-custom/range", "3rc"),
    0xFE: ("const-method-handle", "21c"),
    0xFF: ("const-method-type", "21c"),
}

# Number of 16-bit code units occupied by each instruction format. The leading
# digit of a format id is the code-unit count for every standard format.
FORMAT_UNITS: dict[str, int] = {fmt: int(fmt[0]) for _, fmt in OPCODES.values()}

# Payload pseudo-instructions. The first code unit doubles as an identifier.
PACKED_SWITCH_PAYLOAD = 0x0100
SPARSE_SWITCH_PAYLOAD = 0x0200
FILL_ARRAY_DATA_PAYLOAD = 0x0300

# Constant-pool reference kinds, used to describe the meaning of an index operand.
INDEX_KINDS: dict[str, str] = {
    "21c": "field-or-type-or-string",
    "22c": "field-or-type",
    "31c": "string",
    "35c": "method-or-type",
    "3rc": "method-or-type",
    "45cc": "method",
    "4rcc": "method",
}

# The format id alone is ambiguous for a few opcodes (e.g. 21c is used by both
# const-string and sget). The pool an index refers to is determined by the
# opcode, so map each index-bearing opcode to the pool it indexes: one of
# "string", "type", "field", "method" or "proto".
INDEX_POOL_BY_OPCODE: dict[int, str] = {
    0x1A: "string",  # const-string
    0x1B: "string",  # const-string/jumbo
    0x1C: "type",  # const-class
    0x1F: "type",  # check-cast
    0x20: "type",  # instance-of
    0x22: "type",  # new-instance
    0x23: "type",  # new-array
    0x24: "type",  # filled-new-array
    0x25: "type",  # filled-new-array/range
    0xFE: "method",  # const-method-handle
    0xFF: "proto",  # const-method-type
}
# iget/iput (0x52-0x5f) and sget/sput (0x60-0x6d) reference the field pool.
INDEX_POOL_BY_OPCODE.update({op: "field" for op in range(0x52, 0x60)})
INDEX_POOL_BY_OPCODE.update({op: "field" for op in range(0x60, 0x6E)})
# invoke-* (0x6e-0x72, 0x74-0x78) and the polymorphic/custom calls (0xfa-0xfd)
# reference the method pool.
INDEX_POOL_BY_OPCODE.update({op: "method" for op in range(0x6E, 0x73)})
INDEX_POOL_BY_OPCODE.update({op: "method" for op in range(0x74, 0x79)})
INDEX_POOL_BY_OPCODE.update({op: "method" for op in (0xFA, 0xFB, 0xFC, 0xFD)})


def _clean_descriptor(value) -> str:
    """Normalize a LIEF dex type/class descriptor to ``str`` defensively."""
    try:
        return str(value)
    except (RuntimeError, TypeError):  # nanobind bad_cast on odd entries
        return ""


class DexPools:
    """
    Resolved constant pools for a single dex file.

    LIEF exposes the dex string/type/field/method tables in index order via
    ``DEX.File.strings`` / ``.types`` / ``.fields`` / ``.methods``. This holds
    those tables (pre-rendered to descriptor strings) so a decoded instruction's
    constant-pool ``index`` can be resolved to a human-readable target.
    """

    def __init__(
        self,
        strings: List[str],
        types: List[str],
        fields: List[str],
        methods: List[str],
        protos: Optional[List[str]] = None,
    ) -> None:
        self.strings = strings
        self.types = types
        self.fields = fields
        self.methods = methods
        self.protos = protos or []

    @classmethod
    def from_dex(cls, dexfile) -> "DexPools":
        """
        Build pools from a parsed LIEF dex object (``lief.DEX.parse(...)``).

        Each table is rendered to a smali-like descriptor string. Rendering of
        any single entry is guarded so a malformed entry never aborts the build.
        """
        strings = [str(s) for s in getattr(dexfile, "strings", [])]
        types = [_clean_descriptor(t) for t in getattr(dexfile, "types", [])]
        fields = [cls._render_field(f) for f in getattr(dexfile, "fields", [])]
        methods = [cls._render_method(m) for m in getattr(dexfile, "methods", [])]
        return cls(strings, types, fields, methods)

    @classmethod
    def from_metadata(cls, metadata: dict) -> "DexPools":
        """
        Build pools from a ``parse_dex`` metadata dict.

        ``parse_dex`` already materializes the ``strings`` / ``types`` /
        ``fields`` / ``methods`` lists in index order, so this avoids re-parsing
        the dex file when the metadata is already in hand.
        """
        strings = [str(s) for s in (metadata.get("strings") or [])]
        types = [_clean_descriptor(t) for t in (metadata.get("types") or [])]
        fields = [cls._render_field(f) for f in (metadata.get("fields") or [])]
        methods = [cls._render_method(m) for m in (metadata.get("methods") or [])]
        return cls(strings, types, fields, methods)

    @staticmethod
    def _render_field(fieldobj) -> str:
        """Render a field as ``Lcls;->name:type``."""
        try:
            owner = fieldobj.cls.fullname if fieldobj.has_class else ""
            return f"{owner}->{fieldobj.name}:{_clean_descriptor(fieldobj.type)}"
        except (AttributeError, RuntimeError, TypeError):
            return getattr(fieldobj, "name", "") or ""

    @staticmethod
    def _render_method(methodobj) -> str:
        """Render a method as ``Lcls;->name(params)ret`` (smali signature)."""
        try:
            owner = methodobj.cls.fullname if methodobj.has_class else ""
            proto = methodobj.prototype
            params = "".join(_clean_descriptor(p) for p in proto.parameters_type)
            ret = _clean_descriptor(proto.return_type)
            return f"{owner}->{methodobj.name}({params}){ret}"
        except (AttributeError, RuntimeError, TypeError):
            return getattr(methodobj, "name", "") or ""

    def _lookup(self, pool: List[str], index: int) -> Optional[str]:
        if 0 <= index < len(pool):
            return pool[index]
        return None

    def resolve(self, opcode: int, fmt: str, index: int) -> Optional[str]:
        """Resolve a constant-pool index to its descriptor for the given opcode."""
        pool = INDEX_POOL_BY_OPCODE.get(opcode)
        if pool is None:
            # Fall back on the format's declared kind (e.g. 22c is always type
            # for instance-of/new-array, already handled above; const ops below).
            return None
        if pool == "string":
            return self._lookup(self.strings, index)
        if pool == "type":
            return self._lookup(self.types, index)
        if pool == "field":
            return self._lookup(self.fields, index)
        if pool == "method":
            return self._lookup(self.methods, index)
        if pool == "proto":
            return self._lookup(self.protos, index)
        return None


@dataclass
class Instruction:
    """A single decoded Dalvik instruction."""

    offset: int  # offset of this instruction in 16-bit code units
    opcode: int
    name: str
    fmt: str
    length: int  # length in 16-bit code units
    registers: List[int] = field(default_factory=list)
    literal: Optional[int] = None
    branch: Optional[int] = None  # relative branch target in code units
    index: Optional[int] = None  # constant-pool index
    proto_index: Optional[int] = None  # second index for polymorphic calls
    target: Optional[str] = None  # resolved descriptor for the pool index

    def to_smali(self) -> str:
        """Render the instruction in a smali-like textual form."""
        parts = [self.name]
        operands = [f"v{r}" for r in self.registers]
        if self.literal is not None:
            operands.append(f"#{self.literal}")
        if self.branch is not None:
            operands.append(f"+{self.branch}")
        if self.index is not None:
            if self.target is not None:
                operands.append(self.target)
            else:
                kind = INDEX_KINDS.get(self.fmt, "index")
                operands.append(f"{kind}@{self.index}")
        if self.proto_index is not None:
            operands.append(f"proto@{self.proto_index}")
        if operands:
            parts.append(", ".join(operands))
        return " ".join(parts)


def _to_bytes(bytecode: Union[bytes, bytearray, list]) -> bytes:
    """Normalize a bytecode operand (bytes / bytearray / list of ints) to bytes."""
    if isinstance(bytecode, (bytes, bytearray)):
        return bytes(bytecode)
    return bytes(bytearray(bytecode))


def _u16(data: bytes, unit: int) -> int:
    """Read the unsigned 16-bit code unit at the given code-unit index."""
    off = unit * 2
    return data[off] | (data[off + 1] << 8)


def _sign(value: int, bits: int) -> int:
    """Interpret an unsigned value of the given bit width as signed."""
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)


def _payload_units(ident: int, data: bytes, unit: int, total_units: int) -> int:
    """Compute the code-unit length of a payload pseudo-instruction."""
    if unit + 2 > total_units:
        return 1
    size = _u16(data, unit + 1)
    if ident == PACKED_SWITCH_PAYLOAD:
        return size * 2 + 4
    if ident == SPARSE_SWITCH_PAYLOAD:
        return size * 4 + 2
    # fill-array-data-payload: ident, element_width, 32-bit size, then data.
    element_width = size  # the code unit after ident is the element width here
    if unit + 4 > total_units:
        return 1
    count = _u16(data, unit + 2) | (_u16(data, unit + 3) << 16)
    return (count * element_width + 1) // 2 + 4


def _decode_operands(inst: Instruction, data: bytes, unit: int) -> None:
    """Populate registers / literal / branch / index for an instruction."""
    fmt = inst.fmt
    unit0 = _u16(data, unit)
    high = unit0 >> 8  # the AA / B|A byte above the opcode
    if fmt == "10x":
        return
    if fmt == "12x":
        inst.registers = [high & 0x0F, high >> 4]
    elif fmt == "11n":
        inst.registers = [high & 0x0F]
        inst.literal = _sign(high >> 4, 4)
    elif fmt in ("11x",):
        inst.registers = [high]
    elif fmt == "10t":
        inst.branch = _sign(high, 8)
    elif fmt == "20t":
        inst.branch = _sign(_u16(data, unit + 1), 16)
    elif fmt == "22x":
        inst.registers = [high, _u16(data, unit + 1)]
    elif fmt == "21t":
        inst.registers = [high]
        inst.branch = _sign(_u16(data, unit + 1), 16)
    elif fmt == "21s":
        inst.registers = [high]
        inst.literal = _sign(_u16(data, unit + 1), 16)
    elif fmt == "21h":
        inst.registers = [high]
        inst.literal = _sign(_u16(data, unit + 1), 16)
    elif fmt == "21c":
        inst.registers = [high]
        inst.index = _u16(data, unit + 1)
    elif fmt == "23x":
        bbcc = _u16(data, unit + 1)
        inst.registers = [high, bbcc & 0xFF, bbcc >> 8]
    elif fmt == "22b":
        bbcc = _u16(data, unit + 1)
        inst.registers = [high, bbcc & 0xFF]
        inst.literal = _sign(bbcc >> 8, 8)
    elif fmt == "22t":
        inst.registers = [high & 0x0F, high >> 4]
        inst.branch = _sign(_u16(data, unit + 1), 16)
    elif fmt == "22s":
        inst.registers = [high & 0x0F, high >> 4]
        inst.literal = _sign(_u16(data, unit + 1), 16)
    elif fmt == "22c":
        inst.registers = [high & 0x0F, high >> 4]
        inst.index = _u16(data, unit + 1)
    elif fmt == "30t":
        inst.branch = _sign(_u16(data, unit + 1) | (_u16(data, unit + 2) << 16), 32)
    elif fmt == "32x":
        inst.registers = [_u16(data, unit + 1), _u16(data, unit + 2)]
    elif fmt == "31i":
        inst.registers = [high]
        inst.literal = _sign(_u16(data, unit + 1) | (_u16(data, unit + 2) << 16), 32)
    elif fmt == "31t":
        inst.registers = [high]
        inst.branch = _sign(_u16(data, unit + 1) | (_u16(data, unit + 2) << 16), 32)
    elif fmt == "31c":
        inst.registers = [high]
        inst.index = _u16(data, unit + 1) | (_u16(data, unit + 2) << 16)
    elif fmt in ("35c",):
        _decode_35c(inst, data, unit, high)
    elif fmt == "45cc":
        _decode_35c(inst, data, unit, high)
        inst.proto_index = _u16(data, unit + 3)
    elif fmt == "3rc":
        _decode_3rc(inst, data, unit, high)
    elif fmt == "4rcc":
        _decode_3rc(inst, data, unit, high)
        inst.proto_index = _u16(data, unit + 3)
    elif fmt == "51l":
        inst.registers = [high]
        lo = _u16(data, unit + 1) | (_u16(data, unit + 2) << 16)
        hi = _u16(data, unit + 3) | (_u16(data, unit + 4) << 16)
        inst.literal = _sign(lo | (hi << 32), 64)


def _decode_35c(inst: Instruction, data: bytes, unit: int, high: int) -> None:
    """Decode the register list of a 35c / 45cc (invoke-kind) instruction."""
    count = high >> 4
    g = high & 0x0F
    inst.index = _u16(data, unit + 1)
    cdef = _u16(data, unit + 2)
    regs = [cdef & 0x0F, (cdef >> 4) & 0x0F, (cdef >> 8) & 0x0F, (cdef >> 12) & 0x0F, g]
    inst.registers = regs[: min(count, 5)]


def _decode_3rc(inst: Instruction, data: bytes, unit: int, high: int) -> None:
    """Decode the register range of a 3rc / 4rcc (invoke-range) instruction."""
    count = high
    inst.index = _u16(data, unit + 1)
    first = _u16(data, unit + 2)
    inst.registers = list(range(first, first + count))


def decode(
    bytecode: Union[bytes, bytearray, list], pools: Optional[DexPools] = None
) -> List[Instruction]:
    """
    Decode raw Dalvik bytecode into a list of instructions.

    Args:
        bytecode: The raw bytecode for a method (e.g. ``lief.DEX.Method.bytecode``).
        pools: Optional resolved dex constant pools. When supplied, each
            instruction's constant-pool ``index`` is also resolved to a
            descriptor string in ``Instruction.target``.

    Returns:
        The decoded instructions in order. Payload pseudo-instructions are
        returned as instructions named ``*-payload`` so the stream length is
        accounted for; their operands are not decoded.
    """
    data = _to_bytes(bytecode)
    total_units = len(data) // 2
    instructions: List[Instruction] = []
    unit = 0
    while unit < total_units:
        unit0 = _u16(data, unit)
        opcode = unit0 & 0xFF
        if opcode == 0x00 and (unit0 >> 8) != 0:
            ident = unit0
            length = _payload_units(ident, data, unit, total_units)
            name = {
                PACKED_SWITCH_PAYLOAD: "packed-switch-payload",
                SPARSE_SWITCH_PAYLOAD: "sparse-switch-payload",
                FILL_ARRAY_DATA_PAYLOAD: "fill-array-data-payload",
            }.get(ident, "unknown-payload")
            instructions.append(
                Instruction(offset=unit, opcode=opcode, name=name, fmt="payload", length=length)
            )
            unit += max(length, 1)
            continue
        name, fmt = OPCODES.get(opcode, (f"unknown-0x{opcode:02x}", "10x"))
        length = FORMAT_UNITS.get(fmt, 1)
        # Guard against a truncated trailing instruction.
        if unit + length > total_units:
            instructions.append(
                Instruction(offset=unit, opcode=opcode, name=name, fmt=fmt, length=length)
            )
            break
        inst = Instruction(offset=unit, opcode=opcode, name=name, fmt=fmt, length=length)
        _decode_operands(inst, data, unit)
        if pools is not None and inst.index is not None:
            inst.target = pools.resolve(opcode, fmt, inst.index)
        instructions.append(inst)
        unit += length
    return instructions


def disassemble_method(method, pools: Optional[DexPools] = None) -> List[Instruction]:
    """
    Disassemble a LIEF DEX method.

    Args:
        method: A ``lief.DEX.Method`` whose ``bytecode`` attribute holds the raw
            Dalvik bytecode.

    Returns:
        The decoded instructions, or an empty list when the method has no code.
    """
    bytecode = getattr(method, "bytecode", None)
    if not bytecode:
        return []
    return decode(bytecode, pools)


def opcode_histogram(instructions: List[Instruction]) -> dict[str, int]:
    """Count instructions by mnemonic - a compact summary for analysis."""
    histogram: dict[str, int] = {}
    for inst in instructions:
        histogram[inst.name] = histogram.get(inst.name, 0) + 1
    return histogram
