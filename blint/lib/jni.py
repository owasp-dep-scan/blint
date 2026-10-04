"""JNI surface facts for Android native libraries.

Static registration: a native method's implementation is exported under a
name the JNI specification's "Resolving Native Method Names" chapter
defines (Java SE 24): ``Java_`` + escaped binary class name (``/`` ->
``_``) + ``_`` + escaped method name, plus ``__`` + the escaped parameter
descriptors when the declaration is overloaded. Escapes: ``_`` -> ``_1``,
``;`` -> ``_2``, ``[`` -> ``_3``, any other non-alphanumeric-ASCII UTF-16
unit -> ``_0wxyz`` (lowercase hex; ``$`` = ``_00024``).

The decode is reversible because a literal ``_`` in an identifier always
encodes as ``_1``: the class/method separator is the last ``_`` that does
not start an escape, and the overload suffix is the first ``__`` whose
tail decodes to a valid parameter-descriptor run (a ``__`` whose tail is
not a descriptor is the separator plus a ``_1``-escaped leading
underscore in the method name).

Dynamic registration (``RegisterNatives``) and the dex <-> native join
live here too: ``JNINativeMethod`` tables are recovered from relocations,
and dex ``native`` methods are joined to both surfaces.
"""

from __future__ import annotations

import contextlib
import re

import lief

from blint.lib.binary_common import SHF_EXECINSTR
from blint.logger import LOG

# Escapes per the JNI spec table (Java SE 24). The reverse mapping is
# positional: _1 _, _2 ;, _3 [, _0wxyz U+wxyz (lowercase hex).
_ESCAPES = {"1": "_", "2": ";", "3": "["}
_HEX4_RE = re.compile(r"^[0-9a-f]{4}$")

JNI_ON_LOAD = "JNI_OnLoad"
JNI_ON_UNLOAD = "JNI_OnUnload"


def _unescape(
    text: str, bare_underscore: str, *, strict_bare: bool = False
) -> tuple[str, str | None]:
    """Decode one escaped component; ``bare_underscore`` is what a plain
    ``_`` means there (``/`` for class names and descriptors). Method names
    never carry a bare ``_`` (a literal underscore encodes as ``_1``), so
    ``strict_bare`` makes one a decode error instead."""
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char != "_":
            out.append(char)
            index += 1
            continue
        if index + 1 >= len(text):
            return "".join(out), "trailing_escape"
        nxt = text[index + 1]
        if nxt in _ESCAPES:
            out.append(_ESCAPES[nxt])
            index += 2
        elif nxt == "0":
            hex4 = text[index + 2 : index + 6]
            if not _HEX4_RE.match(hex4):
                return "".join(out), f"bad_unicode_escape_at_{index}"
            out.append(chr(int(hex4, 16)))
            index += 6
        elif strict_bare:
            return "".join(out), "bare_underscore_in_method_name"
        else:
            out.append(bare_underscore)
            index += 1
    return "".join(out), None


def _valid_param_descriptors(text: str) -> bool:
    """True when ``text`` is a concatenation of JVM field descriptors."""
    index, depth = 0, 0
    while index < len(text):
        char = text[index]
        if char == "[":
            index += 1
            depth += 1
            if depth > 255:
                return False
            continue
        if char == "L":
            end = text.find(";", index)
            if end < 0:
                return False
            index = end + 1
        elif char in "BCSIJFDZ":
            index += 1
        else:
            return False
        depth = 0
    return True


def decode_jni_symbol(symbol: str) -> dict:
    """Decode one ``Java_*`` export name into (class, method, signature?).

    Returns ``{symbol, class, method[, signature]}`` on success and
    ``{symbol, decode_error}`` on failure - never drops the symbol.
    """
    if not symbol.startswith("Java_"):
        return {"symbol": symbol, "decode_error": "missing_Java_prefix"}
    rest = symbol[len("Java_") :]

    def attempt(text: str, split_signature: bool = True) -> dict:
        head, sep, tail = text.partition("__")
        if not split_signature:
            head, sep, tail = text, "", ""
        cut = -1
        for index in range(len(head) - 1):
            if head[index] == "_" and (index + 1 >= len(head) or head[index + 1] not in "0123"):
                cut = index
        if head.endswith("_"):
            cut = len(head) - 1
        if cut < 1 or cut + 1 >= len(head):
            return {"symbol": symbol, "decode_error": "no_class_method_separator"}
        class_name, class_err = _unescape(head[:cut], "/")
        method_name, method_err = _unescape(head[cut + 1 :], "", strict_bare=True)
        if method_err:
            return {"symbol": symbol, "decode_error": method_err}
        if class_err:
            return {"symbol": symbol, "decode_error": class_err}
        result: dict = {
            "symbol": symbol,
            "class": class_name.replace("/", "."),
            "method": method_name,
        }
        if sep:
            signature, sig_err = _unescape(tail, "/")
            if sig_err or not _valid_param_descriptors(signature):
                return {"symbol": symbol, "decode_error": f"bad_signature_suffix_{tail}"}
            result["signature"] = signature
        return result

    primary = attempt(rest)
    # A `__` whose tail is not a descriptor is the separator plus a
    # `_1`-escaped underscore in the method name: retry with the whole
    # text as a plain class_method split before reporting a decode error.
    if "decode_error" in primary and "__" in rest:
        fallback = attempt(rest, split_signature=False)
        if "decode_error" not in fallback:
            return fallback
    return primary


def parse_static_jni_surface(dynamic_symbols: list) -> dict | None:
    """The static JNI surface of one library, from its dynamic symbols.

    The exports are dynamic symbols, so an unstripped and a stripped twin
    of the same build produce the same block. Returns None when the
    library has no JNI surface at all (no ``Java_*`` export and neither
    lifecycle hook) - absent reads as "not present", which for this fact
    is the whole answer.
    """
    static_methods: list[dict] = []
    on_load: dict | None = None
    on_unload: dict | None = None
    for entry in dynamic_symbols or []:
        if not isinstance(entry, dict) or entry.get("is_imported"):
            continue
        name = entry.get("name") or ""
        if not name or not (entry.get("is_function") or entry.get("type") == "FUNC"):
            continue
        if name in (JNI_ON_LOAD, JNI_ON_UNLOAD):
            record = {"symbol": name, "address": entry.get("value")}
            if name == JNI_ON_LOAD:
                on_load = record
            else:
                on_unload = record
        elif name.startswith("Java_"):
            decoded = decode_jni_symbol(name)
            decoded["address"] = entry.get("value")
            static_methods.append(decoded)
    if not static_methods and not on_load and not on_unload:
        return None
    decoded_count = sum(1 for entry in static_methods if "decode_error" not in entry)
    return {
        "static_methods": static_methods,
        "on_load": on_load,
        "on_unload": on_unload,
        "counts": {
            "java_exports": len(static_methods),
            "decoded": decoded_count,
            "decode_errors": len(static_methods) - decoded_count,
        },
    }


# ------------------------------------------------------- dex native facts

_ACC_NATIVE_TOKENS = ("NATIVE",)


def _is_native_access(flags) -> bool:
    """ACC_NATIVE (0x0100, dex format spec) across LIEF's flag shapes.

    LIEF exposes ``access_flags`` as a list of ACCESS_FLAGS enums on some
    builds and as the raw int bitmask on others; both say the same thing.
    """
    if isinstance(flags, int):
        return bool(flags & 0x0100)
    return any(token in str(flag).upper() for flag in flags or [] for token in _ACC_NATIVE_TOKENS)


def lief_type_descriptor(t) -> str:
    """One LIEF dex type as its JVM descriptor (``I``, ``[I``, ``L...;``).

    ``str()`` of a LIEF type is already the descriptor for class types but
    pretty for primitives and arrays (``int``, ``int[]``); ``value`` is the
    PRIMITIVES enum and ``dim`` the array depth, so the descriptor is
    rebuilt from those.
    """
    primitive_letters = {
        "VOID_T": "V",  # LIEF spells the void primitive VOID_T
        "BOOLEAN": "Z",
        "BYTE": "B",
        "SHORT": "S",
        "CHAR": "C",
        "INT": "I",
        "LONG": "J",
        "FLOAT": "F",
        "DOUBLE": "D",
    }
    try:
        dim = int(t.dim or 0)
    except (AttributeError, TypeError, RuntimeError):
        dim = 0
    try:
        value = t.value
    except (AttributeError, TypeError, RuntimeError):
        value = None
    if value is not None:
        # Only the PRIMITIVES enum is a primitive marker; other shapes the
        # binding can return for class types are not descriptors.
        token = str(value).split(".")[-1].upper()
        if token in primitive_letters:
            return "[" * dim + primitive_letters[token]
    rendered = str(t)
    base = rendered if rendered.startswith("L") and rendered.endswith(";") else None
    if base is None:
        try:
            return "[" * dim + lief_type_descriptor(t.underlying_array_type)
        except (AttributeError, TypeError, RuntimeError):
            return rendered
    return "[" * dim + base


def collect_dex_native_facts(dex_metadata: dict) -> dict:
    """Native declarations and loadLibrary call sites from one dex.

    ``natives``: every ACC_NATIVE method as ``{class, name, descriptor}``
    with the class in ``L...;`` form - the declarations that need a native
    implementation from some library. ``load_library``: every
    ``System.loadLibrary(<literal>)`` invoke, with the calling class and
    the string literal in force at the call site (the common
    ``const-string`` immediately before it; a non-literal argument records
    the site with ``library: None`` rather than guessing).
    """
    natives: list[dict] = []
    load_library: list[dict] = []
    methods = dex_metadata.get("methods") or []
    from blint.lib.dalvik import DexPools

    for method in methods:
        try:
            if _is_native_access(method.access_flags):
                owner = method.cls.fullname if method.has_class else ""
                proto = method.prototype
                params = "".join(lief_type_descriptor(t) for t in proto.parameters_type)
                natives.append(
                    {
                        "class": owner,
                        "name": str(method.name),
                        "descriptor": f"({params}){lief_type_descriptor(proto.return_type)}",
                        # The dex callgraph node name for this declaration,
                        # rendered by the same DexPools method the callgraph
                        # builds its names from - never a re-derived string
                        # (this LIEF renders Z as `bool`, not `boolean`).
                        "node_name": DexPools._render_method(method),
                    }
                )
        except (AttributeError, RuntimeError, TypeError):
            continue
    # Only a method whose bytecode names System.loadLibrary's method index
    # can call it, so the pools and the decode are paid for those alone.
    load_library_indices = _load_library_method_indices(methods)
    if not load_library_indices:
        return {"natives": natives, "load_library": load_library}
    index_patterns = [index.to_bytes(2, "little") for index in load_library_indices]
    from blint.lib.dalvik import disassemble_method
    from blint.lib.dalvik_semantics import is_invoke

    pools = None
    for method in methods:
        bytecode = getattr(method, "bytecode", None)
        if not bytecode:
            continue
        raw = bytes(bytecode)
        if not any(pattern in raw for pattern in index_patterns):
            continue
        if pools is None:
            try:
                pools = DexPools.from_metadata(dex_metadata)
            except (AttributeError, TypeError, ValueError):
                break
        try:
            instructions = disassemble_method(method, pools)
        except Exception:  # one malformed method must not drop the rest
            continue
        pending_string: str | None = None
        owner = None
        for inst in instructions:
            if inst.name in ("const-string", "const-string/jumbo") and inst.target is not None:
                pending_string = inst.target
            elif is_invoke(inst) and inst.target:
                target = str(inst.target)
                if "Ljava/lang/System;->loadLibrary" in target:
                    if owner is None:
                        owner = method.cls.fullname if getattr(method, "has_class", False) else ""
                    load_library.append({"class": owner or "", "library": pending_string})
    return {"natives": natives, "load_library": load_library}


def _load_library_method_indices(methods: list) -> list[int]:
    """Method-pool indices of ``java.lang.System.loadLibrary`` references."""
    indices = []
    for index, method in enumerate(methods):
        with contextlib.suppress(AttributeError, RuntimeError, TypeError):
            if (
                index <= 0xFFFF
                and str(method.name) == "loadLibrary"
                and method.has_class
                and method.cls.fullname == "Ljava/lang/System;"
            ):
                indices.append(index)
    return indices


# ------------------------------------------- JNA direct-mapping evidence

_JNA_NATIVE_CLASS = "Lcom/sun/jna/Native;"


def _jna_register_indices(methods: list) -> list[int]:
    """Method-pool indices of ``com.sun.jna.Native.register`` overloads."""
    indices = []
    for index, method in enumerate(methods):
        with contextlib.suppress(AttributeError, RuntimeError, TypeError):
            if (
                index <= 0xFFFF
                and str(method.name) == "register"
                and method.has_class
                and method.cls.fullname == _JNA_NATIVE_CLASS
            ):
                indices.append(index)
    return indices


def _jna_direct_mapped_class(
    caller: str, native_classes: set[str], defined_classes: set[str]
) -> str | None:
    """The class JNA's caller-class ``register`` overloads bind: the calling
    class when it declares a native method, else the nearest enclosing
    class that does (JNA's ``findDirectMappedClass``). None when the walk
    reaches a class this dex does not define."""
    cls = caller
    while cls in defined_classes:
        if cls in native_classes:
            return cls
        if "$" not in cls:
            return None
        cls = cls.rsplit("$", 1)[0]
    return None


def _jna_helper_constant(
    methods_by_key: dict[str, object], pools, helper: str | None, depth: int = 2
) -> str | None:
    """The one constant a helper returns: the string constant held on every
    path to a ``return-object``, or the constant a returned call's own
    helper yields (one step per ``depth``, uniffi's Kotlin ``access$``
    accessor in front of ``findLibraryName``). A return of a computed value
    (uniffi's property override) names no constant. None unless exactly one
    constant remains."""
    if not helper or depth < 0:
        return None
    method = methods_by_key.get(helper)
    if method is None or not getattr(method, "bytecode", None):
        return None
    from blint.lib.dalvik import disassemble_method
    from blint.lib.dalvik_dataflow import INVOKE_RESULT, STRING, analyze

    try:
        instructions = disassemble_method(method, pools)
        flow = analyze(instructions)
    except Exception:  # one malformed method must not drop the evidence
        return None
    constants: set[str] = set()
    for inst in instructions:
        if inst.name != "return-object" or not inst.registers:
            continue
        value = flow.state_before.get(inst.offset, {}).get(inst.registers[0])
        if value is None:
            continue
        if value.kind == STRING:
            constants.add(value.value)
        elif value.kind == INVOKE_RESULT:
            constant = _jna_helper_constant(methods_by_key, pools, str(value.value), depth - 1)
            if constant is not None:
                constants.add(constant)
    return next(iter(constants)) if len(constants) == 1 else None


def collect_jna_register_facts(dex_metadata: dict) -> dict[str, dict]:
    """JNA direct-mapping registration evidence from one dex.

    Returns ``{dotted class: {"library": name-or-None}}`` for every class a
    ``com.sun.jna.Native.register`` call in this dex registers. JNA binds
    each native method of the registered class, at run time, to the
    exported symbol of the same name in the registered library, so this
    evidence is what makes a plain-name export a candidate for those
    declarations. The registered class is the call's ``Class`` argument
    when a class literal holds it on every path to the call; the
    caller-class overloads register the calling class, or the nearest
    enclosing class that declares a native method. A ``Class`` argument
    the dex does not name (a parameter) is evidence for no class, and a
    class that merely calls another class's registrar is never the
    registered one. ``library`` is the string constant the call passes on
    every path, or the one constant the invoked helper returns (uniffi's
    ``findLibraryName`` fallback); None when the name is computed, or when
    two calls registering the class disagree.
    """
    from blint.lib.dalvik import DexPools, disassemble_method
    from blint.lib.dalvik_dataflow import CLASS, INVOKE_RESULT, STRING, analyze

    methods = dex_metadata.get("methods") or []
    register_indices = _jna_register_indices(methods)
    if not register_indices:
        return {}
    native_classes: set[str] = set()
    defined_classes: set[str] = set()
    for method in methods:
        with contextlib.suppress(AttributeError, RuntimeError, TypeError):
            if not method.has_class:
                continue
            owner = _dotted_class(method.cls.fullname)
            if _is_native_access(method.access_flags):
                native_classes.add(owner)
                defined_classes.add(owner)
            elif getattr(method, "bytecode", None):
                defined_classes.add(owner)
    pools: DexPools | None = None
    methods_by_key: dict[str, object] | None = None
    patterns = [index.to_bytes(2, "little") for index in register_indices]
    registered: dict[str, set[str | None]] = {}
    for method in methods:
        bytecode = getattr(method, "bytecode", None)
        if not bytecode:
            continue
        raw = bytes(bytecode)
        if not any(pattern in raw for pattern in patterns):
            continue
        caller = ""
        with contextlib.suppress(AttributeError, RuntimeError, TypeError):
            caller = _dotted_class(method.cls.fullname) if method.has_class else ""
        if not caller or caller.startswith("com.sun.jna."):
            continue
        if pools is None:
            try:
                pools = DexPools.from_metadata(dex_metadata)
            except (AttributeError, TypeError, ValueError):
                break
        try:
            flow = analyze(disassemble_method(method, pools))
        except Exception:
            continue
        for site in flow.call_sites:
            target = str(site.method or "")
            if not target.startswith(f"{_JNA_NATIVE_CLASS}->register("):
                continue
            if target.startswith(f"{_JNA_NATIVE_CLASS}->register(Ljava/lang/Class;"):
                literal = site.arguments[0] if site.arguments else None
                cls = (
                    _dotted_class(str(literal.value))
                    if literal is not None and literal.kind == CLASS
                    else None
                )
            else:
                cls = _jna_direct_mapped_class(caller, native_classes, defined_classes)
            if cls is None:
                continue
            library = None
            name = site.arguments[-1] if "Ljava/lang/String;)" in target else None
            if name is not None and name.kind == STRING:
                library = name.value
            elif name is not None and name.kind == INVOKE_RESULT:
                if methods_by_key is None:
                    methods_by_key = {}
                    for candidate in methods:
                        rendered = DexPools._render_method(candidate)
                        if rendered and "->" in rendered:
                            methods_by_key.setdefault(rendered, candidate)
                library = _jna_helper_constant(methods_by_key, pools, str(name.value))
            registered.setdefault(cls, set()).add(library)
    return {
        cls: {"library": next(iter(libraries)) if len(libraries) == 1 else None}
        for cls, libraries in registered.items()
    }


# ----------------------------------------------------- the static join


def _dotted_class(cls: str) -> str:
    if cls.startswith("L") and cls.endswith(";"):
        cls = cls[1:-1]
    return cls.replace("/", ".")


def _param_descriptor(descriptor: str) -> str:
    end = descriptor.find(")")
    return descriptor[1:end] if descriptor.startswith("(") and end > 0 else descriptor


def join_static(dex_natives: list[dict], surface: dict | None) -> dict:
    """Join dex native declarations to one library's static surface.

    ``bound`` entries carry the dex declaration and the export that
    implements it; ``unbound_dex_natives`` are the declarations this
    library does not answer (likely registered dynamically, loaded from
    elsewhere, or missing); ``undeclared_exports`` are the library's
    ``Java_*`` exports with no dex declaration (plus any that do not
    decode). Matching is by class and method name, and by parameter
    descriptors whenever the dex class overloads the name or the export
    carries the ``__<sig>`` form.
    """
    static_methods = (surface or {}).get("static_methods") or []
    name_counts: dict[tuple[str, str], int] = {}
    for native in dex_natives:
        key = (_dotted_class(native["class"]), native["name"])
        name_counts[key] = name_counts.get(key, 0) + 1
    bound: list[dict] = []
    used: set[str] = set()
    unbound: list[dict] = []
    for native in dex_natives:
        cls = _dotted_class(native["class"])
        overloaded = name_counts[(cls, native["name"])] > 1
        candidates = [
            entry
            for entry in static_methods
            if "decode_error" not in entry
            and entry.get("class") == cls
            and entry.get("method") == native["name"]
        ]
        chosen = None
        if overloaded:
            chosen = next(
                (
                    e
                    for e in candidates
                    if e.get("signature") == _param_descriptor(native["descriptor"])
                ),
                None,
            )
        else:
            chosen = next((e for e in candidates if "signature" not in e), None) or next(
                (
                    e
                    for e in candidates
                    if e.get("signature") == _param_descriptor(native["descriptor"])
                ),
                None,
            )
        if chosen:
            used.add(chosen["symbol"])
            bound.append(
                {
                    **native,
                    "class": cls,
                    "symbol": chosen["symbol"],
                    "fn_addr": chosen.get("address"),
                }
            )
        else:
            unbound.append({**native, "class": cls})
    undeclared = [entry for entry in static_methods if entry["symbol"] not in used]
    return {"bound": bound, "unbound_dex_natives": unbound, "undeclared_exports": undeclared}


# ---------------------------------------------------- the app-level summary

# Listing bound for the exported summary, the same shape of cap the other
# app summaries use. The callgraph's JNI edges and the reviews read the
# full join (``build_jni_join_summary(..., capped=False)``); only the
# metadata copy is cut (``cap_jni_join``).
JOIN_LISTING_CAP = 256
_JOIN_LISTS = (
    "bound",
    "bound_dynamic",
    "ambiguous_dynamic",
    "unbound_dex_natives",
    "undeclared_exports",
)


def _cap_join_lists(abi_join: dict) -> dict:
    """One ABI's join with each list cut to its first ``JOIN_LISTING_CAP``
    entries and a ``<list>_truncated`` flag beside a cut one."""
    capped = dict(abi_join)
    for key in _JOIN_LISTS:
        full = abi_join.get(key) or []
        capped[key] = full[:JOIN_LISTING_CAP]
        if len(full) > JOIN_LISTING_CAP:
            capped[f"{key}_truncated"] = True
    return capped


def cap_jni_join(join: dict) -> dict:
    """The metadata copy of a full join summary: every listing cut to
    ``JOIN_LISTING_CAP`` entries, the counts untouched."""
    capped = dict(join)
    capped["load_library"] = (join.get("load_library") or [])[:JOIN_LISTING_CAP]
    capped["per_abi"] = {
        abi: _cap_join_lists(abi_join) for abi, abi_join in (join.get("per_abi") or {}).items()
    }
    return capped


def _slot_address(table_entry: dict) -> int | None:
    """The entry's own triple address (``slot``), as an int."""
    slot = table_entry.get("slot")
    if isinstance(slot, str):
        with contextlib.suppress(ValueError):
            return int(slot, 16)
    return slot if isinstance(slot, int) else None


def _registration_covers(
    match: dict, confirmed_ranges: dict[tuple[str, str], list[dict]], abi: str
) -> bool:
    """True when some resolved registration range covers this candidate
    entry's own slot in its library's copy of the ABI."""
    slot = _slot_address(match)
    if slot is None:
        return False
    return any(
        entry_range["begin"] <= slot < entry_range["end"]
        for entry_range in (confirmed_ranges or {}).get((match["library"], abi), [])
    )


def _join_abi_lists(
    natives: list[dict],
    surfaces: dict[tuple[str, str], dict | None],
    register_tables: dict[tuple[str, str], dict],
    lib_abis: dict[str, set[str]],
    abi: str,
    confirmed_ranges: dict[tuple[str, str], list[dict]] | None = None,
    runtime_registrations: dict[tuple[str, str], list[dict]] | None = None,
    jna_registers: dict[str, dict] | None = None,
    jna_dispatch_abis: set[str] | None = None,
    plain_exports: dict[tuple[str, str], dict[str, str] | None] | None = None,
    capped: bool = True,
) -> dict:
    """One ABI's join across every library that ships in it.

    ``surfaces``, ``register_tables`` and ``confirmed_ranges`` are keyed by
    ``(library, abi)`` - each ABI's own copy of the library,
    never another ABI's bytes standing in for a missing one. A dex
    declaration binds at most once (first library in name order):
    statically to a decoded export, or - for what no export answers -
    dynamically to a recovered JNINativeMethod table entry whose name and
    signature both match (the class is unknown in the table, so signature
    equality is required, and the pair must be unique on both sides;
    otherwise the declarations are listed as ambiguous_dynamic with the
    number of candidate entries). An ambiguous declaration binds when
    the registering function chain's constant class name - the
    ``FindClass`` confirmer's answer, per (library, abi) and table - names
    exactly one of the pair's declaring classes and exactly one candidate
    entry names it; anything the confirmer cannot decide stays ambiguous.
    What no table answers can still bind by name through JNA direct
    mapping - a ``Native.register`` call in the dex registers the
    declaring class, ``libjnidispatch.so`` ships in this
    ABI, and exactly one same-ABI library exports the name (the register
    call's constant names the library when there is one, JNA mapping
    ``foo`` to ``libfoo.so``); those rows carry ``confirmed_by:
    "jna_direct"``, and a name more than one library exports is listed
    ambiguous with every exporter. What nothing answers is unbound, and
    each library's unclaimed exports are its undeclared list. An
    ambiguous declaration whose candidate entries all sit inside ranges
    the confirmer resolved, in an ABI where no resolved registration
    names its class, carries ``candidates_registered_elsewhere``: a mark,
    not a binding. Its own registration, if any, is in a table the join
    did not recover. Counts reflect the full sets; unless ``capped`` is
    False the lists are cut at ``JOIN_LISTING_CAP`` with a ``truncated``
    flag.
    """
    bound: list[dict] = []
    bound_dynamic: list[dict] = []
    unbound: list[dict] = []
    undeclared: list[dict] = []
    ambiguous: list[dict] = []
    answered: set[tuple[str, str, str]] = set()
    for name in sorted(lib_abis):
        if abi not in lib_abis[name]:
            continue
        result = join_static(natives, surfaces.get((name, abi)))
        for entry in result["bound"]:
            key = (entry["class"], entry["name"], entry["descriptor"])
            if key not in answered:
                answered.add(key)
                bound.append({**entry, "abi": abi, "library": name})
        undeclared.extend(
            {**entry, "abi": abi, "library": name} for entry in result["undeclared_exports"]
        )
    # The table carries no class, so a (name, signature) pair binds only
    # when it is unique on both sides: one unanswered declaring class and
    # one table entry in this ABI. fbjni-style names (disposeNative()V,
    # initHybrid) repeat across classes; binding those would pick an
    # arbitrary implementation.
    pending: dict[tuple[str, str], dict[str, dict]] = {}
    for native_entry in natives:
        cls = _dotted_class(native_entry["class"])
        if (cls, native_entry["name"], native_entry["descriptor"]) in answered:
            continue
        pair = (native_entry["name"], native_entry["descriptor"])
        pending.setdefault(pair, {}).setdefault(cls, native_entry)
    table_entries: dict[tuple[str, str], list[dict]] = {}
    for name in sorted(lib_abis):
        if abi not in lib_abis[name]:
            continue
        for table in (register_tables.get((name, abi)) or {}).get("tables") or []:
            for table_entry in table.get("entries") or []:
                pair = (table_entry.get("name"), table_entry.get("signature"))
                if pair in pending:
                    table_entries.setdefault(pair, []).append({**table_entry, "library": name})
        # Registrations recovered from the registrar walk's stores (tables
        # built at run time): each entry carries the class its FindClass
        # named, so it decides only that class's rows.
        for registration in (runtime_registrations or {}).get((name, abi)) or []:
            for table_entry in registration.get("entries") or []:
                pair = (table_entry.get("name"), table_entry.get("signature"))
                if pair in pending:
                    table_entries.setdefault(pair, []).append(
                        {
                            **table_entry,
                            "library": name,
                            "runtime_class": registration.get("class"),
                        }
                    )
    # The classes this ABI's resolved registrations name.
    named_classes = {
        entry_range["class"]
        for (_, range_abi), ranges in (confirmed_ranges or {}).items()
        if range_abi == abi
        for entry_range in ranges
    }
    # JNA direct mapping binds by exported name; the per-ABI view of the
    # plain exports is built once.
    jna_name_exports: dict[str, list[tuple[str, str]]] = {}
    jna_here = bool(jna_registers) and abi in (jna_dispatch_abis or set())
    if jna_here:
        for (name, export_abi), exports in (plain_exports or {}).items():
            if export_abi != abi or not exports:
                continue
            for export_name, value in exports.items():
                jna_name_exports.setdefault(export_name, []).append((name, value))
    for pair, classes in pending.items():
        matches = table_entries.get(pair) or []
        if len(matches) == 1 and len(classes) == 1:
            cls, native_entry = next(iter(classes.items()))
            match = matches[0]
            runtime_class = match.get("runtime_class")
            if runtime_class and runtime_class != cls:
                # registered for a class the dex does not declare it on
                unbound.append({**native_entry, "class": cls, "abi": abi})
                continue
            bound_dynamic.append(
                {
                    **native_entry,
                    "class": cls,
                    "abi": abi,
                    "library": match["library"],
                    "fn_addr": match.get("fn_addr"),
                    **({"fn_name": match["fn_name"]} if match.get("fn_name") else {}),
                    **({"confirmed_by": "runtime_table"} if runtime_class else {}),
                }
            )
            continue
        # A class binds when exactly one candidate entry sits in a
        # registration range the FindClass confirmer resolved to exactly
        # that class. An entry covered by ranges naming two declaring
        # classes decides nothing, and a class with two clean entries is
        # still an arbitrary pick - both stay ambiguous.
        decided: dict[str, dict] = {}
        for cls in classes:
            clean = []
            seen_picks: set[tuple] = set()
            for match in matches:
                # identical implementations (the same entry recovered
                # twice) are one pick, not an arbitrary choice between two;
                # a runtime entry of another class is a different pick even
                # when the fn matches - it names that class's registration
                pick = (
                    match["library"],
                    match.get("fn_addr"),
                    match.get("name"),
                    match.get("runtime_class") or _slot_address(match),
                )
                if pick in seen_picks:
                    continue
                seen_picks.add(pick)
                if match.get("runtime_class"):
                    # a runtime-recovered entry names its own class
                    if match["runtime_class"] == cls:
                        clean.append(match)
                    continue
                slot = _slot_address(match)
                naming = {
                    entry_range["class"]
                    for entry_range in (confirmed_ranges or {}).get((match["library"], abi), [])
                    if slot is not None
                    and entry_range["begin"] <= slot < entry_range["end"]
                    and entry_range["class"] in classes
                }
                if naming == {cls}:
                    clean.append(match)
            if len(clean) == 1:
                decided[cls] = clean[0]
        for cls, native_entry in classes.items():
            if cls in decided:
                match = decided[cls]
                bound_dynamic.append(
                    {
                        **native_entry,
                        "class": cls,
                        "abi": abi,
                        "library": match["library"],
                        "fn_addr": match.get("fn_addr"),
                        **({"fn_name": match["fn_name"]} if match.get("fn_name") else {}),
                        "confirmed_by": "runtime_table"
                        if match.get("runtime_class")
                        else "findclass",
                    }
                )
                continue
            record = {**native_entry, "class": cls, "abi": abi}
            if matches:
                record["table_candidates"] = len(matches)
                # Every candidate is registered for some other class, and
                # no resolved registration names this one. Without the
                # confirmer there are no ranges, so no mark.
                if cls not in named_classes and all(
                    _registration_covers(match, confirmed_ranges, abi) for match in matches
                ):
                    record["candidates_registered_elsewhere"] = True
                ambiguous.append(record)
                continue
            # No table answers this pair; JNA direct mapping may still
            # bind it by exported name, when the declaring class
            # registered with JNA and this ABI ships libjnidispatch.so.
            if jna_here and cls in jna_registers:
                register = jna_registers[cls].get("library")
                wanted = f"lib{register}.so" if register else None
                exporters = [
                    (name, value)
                    for name, value in jna_name_exports.get(native_entry["name"]) or []
                    if wanted is None or name == wanted
                ]
                if len(exporters) == 1:
                    library, value = exporters[0]
                    bound_dynamic.append(
                        {
                            **native_entry,
                            "class": cls,
                            "abi": abi,
                            "library": library,
                            "fn_addr": value,
                            "confirmed_by": "jna_direct",
                        }
                    )
                    continue
                if exporters:
                    # two or more exporters of the name and no register
                    # constant to pick one: ambiguous, every exporter listed
                    record["jna_exporters"] = sorted({name for name, _ in exporters})
                    ambiguous.append(record)
                    continue
            unbound.append(record)
    result = {
        "counts": {
            "libraries": sum(1 for name in lib_abis if abi in lib_abis[name]),
            "bound": len(bound),
            "bound_dynamic": len(bound_dynamic),
            "jna_direct": sum(
                1 for entry in bound_dynamic if entry.get("confirmed_by") == "jna_direct"
            ),
            "ambiguous_dynamic": len(ambiguous),
            "unbound_dex_natives": len(unbound),
            "undeclared_exports": len(undeclared),
        },
        "bound": bound,
        "bound_dynamic": bound_dynamic,
        "ambiguous_dynamic": ambiguous,
        "unbound_dex_natives": unbound,
        "undeclared_exports": undeclared,
    }
    return _cap_join_lists(result) if capped else result


def _confirm_ambiguous_tables(
    app_file: str,
    natives: list[dict],
    register_tables: dict[tuple[str, str], dict],
    lib_locations: dict[tuple[str, str], dict],
) -> dict[tuple[str, str], list[dict]]:
    """Per (library, abi): the registration ranges the FindClass confirmer
    resolved - ``[{begin, end, class}]`` over the recovered
    tables' addresses.

    Runs only where the join can be ambiguous at all - (name, signature)
    pairs several dex classes declare, or pairs more than one recovered
    entry answers - and only re-reads the (library, abi) copies that hold
    candidate tables. Apps without such pairs pay one pass over the dex
    facts and nothing else. Any failure degrades to "no
    confirmation": the entries stay ambiguous, never guessed.
    """
    from collections import Counter, defaultdict

    pair_classes: dict[tuple[str, str], set[str]] = defaultdict(set)
    for entry in natives:
        pair_classes[(entry["name"], entry["descriptor"])].add(_dotted_class(entry["class"]))
    wanted = {pair for pair, classes in pair_classes.items() if len(classes) > 1}
    if not wanted:
        entry_counts: Counter = Counter()
        for tables in register_tables.values():
            for table in tables.get("tables") or []:
                for table_entry in table.get("entries") or []:
                    entry_counts[(table_entry.get("name"), table_entry.get("signature"))] += 1
        wanted = {pair for pair, count in entry_counts.items() if count > 1}
    if not wanted:
        return {}
    owners = {
        key: tables
        for key, tables in register_tables.items()
        if key in lib_locations
        and any(
            (entry.get("name"), entry.get("signature")) in wanted
            for table in tables.get("tables") or []
            for entry in table.get("entries") or []
        )
    }
    confirmed: dict[tuple[str, str], list[dict]] = {}
    if not owners:
        return confirmed
    from blint.lib.android_native import LibraryReader
    from blint.lib.jni_findclass import confirm_table_ranges

    try:
        with LibraryReader(app_file) as reader:
            for key, tables in owners.items():
                data = None
                with contextlib.suppress(Exception):
                    data = reader.read(lib_locations[key])
                if not data:
                    continue
                parsed = lief.ELF.parse(data)
                if parsed is None or isinstance(parsed, lief.lief_errors):
                    continue
                with contextlib.suppress(Exception):
                    ranges = confirm_table_ranges(parsed, tables.get("tables") or [])
                    if ranges:
                        confirmed[key] = ranges
    except Exception as exc:
        LOG.debug(f"jni join: findclass confirmation failed for {app_file}: {exc}")
    return confirmed


def _library_join_facts(
    parsed, want_plain_exports: bool = False
) -> tuple[dict | None, dict | None, dict[str, str] | None]:
    """The static JNI surface, the recovered ``RegisterNatives`` tables and
    (on request) the plain exported-FUNC map from one parsed copy of a
    library - the join's light parse (dynamic symbols plus unwind-table function
    starts for stripped builds, not full metadata). The plain map, when
    asked for, is ``{exported FUNC name: address}`` for every defined
    dynamic function - the names JNA direct mapping binds by; it is
    collected only when the app's dex carries ``Native.register``
    evidence, so every other app pays nothing for it."""
    from blint.lib.binary_elf import parse_symbols
    from blint.lib.funcdisc.unwind import discover_functions

    entries, _ = parse_symbols(parsed.dynamic_symbols)
    surface = parse_static_jni_surface(entries)
    plain_exports: dict[str, str] | None = {} if want_plain_exports else None
    # Function starts from the defined dynamic FUNCs plus the unwind
    # tables (stripped builds).
    starts: set[int] = set()
    addr_to_name: dict[int, str] = {}
    for entry in entries or []:
        if not isinstance(entry, dict) or entry.get("is_imported"):
            continue
        if not (entry.get("is_function") or entry.get("type") == "FUNC"):
            continue
        try:
            address = int(entry.get("value") or "0", 16) & ~1
        except (TypeError, ValueError):
            continue
        starts.add(address)
        if entry.get("name"):
            addr_to_name.setdefault(address, entry["name"])
            if plain_exports is not None:
                plain_exports[entry["name"]] = entry.get("value") or hex(address)
    for discovered in discover_functions(parsed) or []:
        # discovery records carry hex strings in metadata form and plain
        # ints from the direct call
        address = discovered.get("address")
        with contextlib.suppress(TypeError, ValueError):
            starts.add((address if isinstance(address, int) else int(address, 16)) & ~1)
    tables = recover_register_natives_tables(parsed, starts, addr_to_name) if starts else None
    if plain_exports is not None and not plain_exports:
        plain_exports = None
    return surface, tables, plain_exports


def build_jni_join_summary(
    app_file: str, native: dict, confirm_findclass: bool = False, capped: bool = True
) -> dict | None:
    """The app-level dex <-> native static join.

    Per ABI (one result per ``(abi, library)``, never a
    silent first-or-best), every dex ``native`` declaration is bound to
    the library whose decoded exports implement it; what no library in
    that ABI answers is reported as unbound (likely dynamic registration,
    another library, or obfuscation), and every export no dex declares is
    reported per library. Each ABI's copy of a library is parsed for its
    own tables and surface, so an ``fn_addr`` always names an address in
    that ABI's bytes; a library that does not ship in an ABI answers
    nothing there - never another ABI's tables in its place. A library
    whose first parsed copy owns neither a static surface nor a recovered
    table is not parsed again for its other ABIs (the same sources build
    every ABI's copy) - unless the app's dex carries JNA
    ``Native.register`` evidence, whose plain-name exports are then part
    of every copy's parse.
    ``System.loadLibrary`` call sites map to ``lib<name>.so`` members.
    Bounded: counts always, the first ``JOIN_LISTING_CAP`` entries of
    each list, ``truncated`` flags beside - or, with ``capped=False``,
    every entry (``cap_jni_join`` cuts that copy later). ``confirm_findclass`` (set by
    ``--disassemble``) runs the FindClass confirmer over the
    (library, abi) copies that hold ambiguous tables and the JNA
    direct-mapping evidence walk over the app's dex; without it no row
    is ever confirmed or marked ``candidates_registered_elsewhere``, and
    no row binds through ``Native.register``.
    """
    from blint.lib.android import _iter_app_dex_files
    from blint.lib.android_native import LibraryReader
    from blint.lib.binary import parse_dex

    natives: list[dict] = []
    load_library: list[dict] = []
    # JNA direct-mapping evidence, from a dex bytecode walk the default
    # join does not do (it decodes only loadLibrary call sites), so it
    # runs only under the confirmers' flag.
    jna_registers: dict[str, dict] = {}
    try:
        for adex, _ in _iter_app_dex_files(app_file):
            dex_metadata = parse_dex(adex)
            facts = collect_dex_native_facts(dex_metadata)
            natives.extend(facts["natives"])
            load_library.extend(facts["load_library"])
            if confirm_findclass:
                jna_registers.update(collect_jna_register_facts(dex_metadata))
    except Exception as exc:  # a malformed app must not abort the analysis
        LOG.debug(f"jni join: dex facts failed for {app_file}: {exc}")
        return None
    if not natives and not load_library:
        return None

    # JNA's dispatch library must ship in an ABI for its bindings to be
    # loadable there at all.
    jna_dispatch_abis = {
        loc.get("abi")
        for lib in native.get("libraries") or []
        if lib.get("name") == "libjnidispatch.so"
        for loc in lib.get("locations") or []
        if loc.get("abi")
    }
    jna_active = bool(jna_registers)

    # One light parse per (library, abi) copy (keyed per ABI); the
    # join needs only the dynamic-symbol surface, not full metadata.
    surfaces: dict[tuple[str, str], dict | None] = {}
    register_tables: dict[tuple[str, str], dict] = {}
    plain_exports: dict[tuple[str, str], dict[str, str] | None] = {}
    abis: set[str] = set()
    lib_abis: dict[str, set[str]] = {}
    lib_locations: dict[tuple[str, str], dict] = {}
    try:
        with LibraryReader(app_file) as reader:
            # The native model lists one entry per (library, abi) - a
            # multi-ABI app repeats the name - so the join groups the
            # locations itself; the first location per (name, abi) wins
            # (split APKs repeat members).
            for lib in native.get("libraries") or []:
                name = lib.get("name") or ""
                if not name or lib.get("not_elf"):
                    continue
                for loc in lib.get("locations") or []:
                    abi = loc.get("abi")
                    if not abi:
                        continue
                    abis.add(abi)
                    lib_abis.setdefault(name, set()).add(abi)
                    lib_locations.setdefault((name, abi), loc)
            by_name: dict[str, list[str]] = {}
            for name, abi in lib_locations:
                by_name.setdefault(name, []).append(abi)
            for name in sorted(by_name):
                parsed_ok = False
                owns = False
                for abi in sorted(by_name[name]):
                    if parsed_ok and not owns and not jna_active:
                        # One successfully parsed copy that owns neither a
                        # surface nor a table settles the library: the same
                        # sources build every ABI's copy, so the remaining
                        # copies are not read. A JNA-registering app keeps
                        # reading: its plain exports are part of the join.
                        continue
                    data = None
                    with contextlib.suppress(Exception):
                        data = reader.read(lib_locations[(name, abi)])
                    if not data:
                        continue
                    try:
                        parsed = lief.ELF.parse(data)
                        if parsed is None or isinstance(parsed, lief.lief_errors):
                            continue
                        parsed_ok = True
                        surface, tables, exports = _library_join_facts(
                            parsed, want_plain_exports=jna_active
                        )
                        surfaces[(name, abi)] = surface
                        if tables:
                            register_tables[(name, abi)] = tables
                        if exports:
                            plain_exports[(name, abi)] = exports
                        owns = owns or surface is not None or tables is not None
                    except Exception as exc:
                        LOG.debug(f"jni join: surface parse failed for {name}: {exc}")
                        continue
    except Exception as exc:
        LOG.debug(f"jni join: library surfaces failed for {app_file}: {exc}")

    per_abi: dict[str, dict] = {}
    confirmed_classes = (
        _confirm_ambiguous_tables(app_file, natives, register_tables, lib_locations)
        if confirm_findclass
        else {}
    )
    for abi in sorted(abis):
        per_abi[abi] = _join_abi_lists(
            natives,
            surfaces,
            register_tables,
            lib_abis,
            abi,
            confirmed_classes,
            jna_registers=jna_registers,
            jna_dispatch_abis=jna_dispatch_abis,
            plain_exports=plain_exports,
            capped=capped,
        )
    # Tables built at run time: where the join leaves dex natives unbound,
    # the registrar walk may still read the entry words off the stack.
    # Only each ABI's own copies are walked, and only i386 word stores
    # with a constant count recover anything.
    runtime_registrations: dict[tuple[str, str], list[dict]] = {}
    if confirm_findclass:
        unbound_abis = {
            abi
            for abi, abi_join in per_abi.items()
            if (abi_join.get("counts") or {}).get("unbound_dex_natives")
        }
        if unbound_abis:
            from blint.lib.jni_findclass import external_pop_resolver, recover_runtime_tables

            try:
                with LibraryReader(app_file) as reader:
                    # i386 walks verify an imported callee's pop in the
                    # same-ABI library that exports it (fbjni's
                    # findClassLocal); without a resolver an imported
                    # callee never shifts the frame.
                    pop_resolvers: dict[str, object] = {}
                    for (name, abi), loc in lib_locations.items():
                        if abi not in unbound_abis:
                            continue
                        data = None
                        with contextlib.suppress(Exception):
                            data = reader.read(loc)
                        if not data:
                            continue
                        parsed = lief.ELF.parse(data)
                        if parsed is None or isinstance(parsed, lief.lief_errors):
                            continue
                        if abi == "x86" and abi not in pop_resolvers:
                            with contextlib.suppress(Exception):
                                pop_resolvers[abi] = external_pop_resolver(
                                    reader.read,
                                    [
                                        sibling
                                        for (_lib, sibling_abi), sibling in lib_locations.items()
                                        if sibling_abi == abi
                                    ],
                                )
                        with contextlib.suppress(Exception):
                            registrations = recover_runtime_tables(
                                parsed, pop_for_external=pop_resolvers.get(abi)
                            )
                            if registrations:
                                runtime_registrations[(name, abi)] = registrations
            except Exception as exc:
                LOG.debug(f"jni join: runtime-table recovery failed for {app_file}: {exc}")
        if runtime_registrations:
            for abi in sorted({key[1] for key in runtime_registrations}):
                per_abi[abi] = _join_abi_lists(
                    natives,
                    surfaces,
                    register_tables,
                    lib_abis,
                    abi,
                    confirmed_classes,
                    runtime_registrations,
                    jna_registers=jna_registers,
                    jna_dispatch_abis=jna_dispatch_abis,
                    plain_exports=plain_exports,
                    capped=capped,
                )

    # loadLibrary("x") -> libx.so member presence, per ABI where it ships.
    member_names = {
        (loc.get("abi") or "", lib.get("name") or "")
        for lib in native.get("libraries") or []
        for loc in lib.get("locations") or []
    }
    load_library_summary = []
    for site in load_library:
        library = site.get("library")
        member = f"lib{library}.so" if library else None
        load_library_summary.append(
            {
                "class": site.get("class"),
                "library": library,
                "member": member,
                "abis": sorted({abi for abi, name in member_names if member and name == member})
                if member
                else [],
            }
        )
    return {
        "counts": {
            "dex_natives": len(natives),
            "load_library_sites": len(load_library),
            "abis": len(abis),
        },
        "load_library": load_library_summary[:JOIN_LISTING_CAP]
        if capped
        else load_library_summary,
        "per_abi": per_abi,
    }


# ------------------------------------------- RegisterNatives tables

# JNI method signatures: "(" descriptors ")" and one return descriptor (V is
# a return type only). Name strings must be Java identifiers.
_JAVA_IDENTIFIER_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")

# A candidate name or signature string is read with this bound: one whose
# NUL does not sit within it is refused, never truncated, so a cut-down
# name or signature cannot bind.
JNI_STRING_READ_LIMIT = 1024


def _read_cstring(parsed_obj, address: int, limit: int = JNI_STRING_READ_LIMIT) -> str | None:
    """The NUL-terminated string at ``address``, or None.

    A string that does not terminate within ``limit`` bytes is None, not
    its truncated prefix - the recovery must not accept a cut-down
    signature or name.
    """
    try:
        content = bytes(parsed_obj.get_content_from_virtual_address(address, limit))
    except (SystemError, Exception):
        return None
    if not content:
        return None
    end = content.find(b"\x00")
    if end <= 0:
        return None
    try:
        return content[:end].decode("utf-8")
    except UnicodeDecodeError:
        return None


def _read_word(parsed_obj, address: int, word_size: int) -> int | None:
    """The little-endian word at ``address`` (REL addends live there)."""
    try:
        content = bytes(parsed_obj.get_content_from_virtual_address(address, word_size))
        return int.from_bytes(content, "little")
    except (SystemError, Exception):
        return None


def _valid_method_signature(text: str) -> bool:
    """``(params)return`` per the JNI signature grammar."""
    if not text or not text.startswith("(") or ")" not in text:
        return False
    params, _, ret = text[1:].partition(")")
    if not _valid_param_descriptors(params):
        return False
    # Exactly one return descriptor: V, or one field descriptor.
    return ret == "V" or (_valid_param_descriptors(ret) and _is_single_descriptor(ret))


def _is_single_descriptor(text: str) -> bool:
    body = text.lstrip("[")
    return (
        len(body) == 1
        and body in "BCSIJFDZ"
        or (body.startswith("L") and body.endswith(";") and body.count(";") == 1)
    )


def relative_relocation_map(parsed_obj) -> tuple[dict[int, int], list[str]]:
    """``{slot address: target VA}`` from every R_*_RELATIVE relocation.

    RELA forms carry the pre-link target in the addend; REL forms (arm32)
    leave it in the stored word. RELR and Android's packed APS2 tables are
    read through LIEF's own decoding; when a packed table the dynamic
    section declares produced no entries, that is recorded as an
    incompleteness note rather than guessed around.
    """
    values: dict[int, int] = {}
    incomplete: list[str] = []
    try:
        word_size = 8 if int(parsed_obj.header.identity[4]) == 2 else 4
    except (AttributeError, IndexError, TypeError):
        word_size = 8
    relocations = []
    with contextlib.suppress(Exception):
        relocations = list(parsed_obj.relocations)
    relative_seen = False
    for relocation in relocations:
        if "RELATIVE" not in str(getattr(relocation, "type", "")):
            continue
        relative_seen = True
        address = int(relocation.address)
        addend = int(getattr(relocation, "addend", 0) or 0)
        if addend:
            values[address] = addend
        else:
            stored = _read_word(parsed_obj, address, word_size)
            if stored:
                values[address] = stored
    packed_declared = False
    with contextlib.suppress(Exception):
        for entry in parsed_obj.dynamic_entries:
            if str(entry.tag) in (
                "TAG.ANDROID_RELA",
                "TAG.ANDROID_REL",
            ):
                packed_declared = True
    if packed_declared and not relative_seen:
        incomplete.append("android_packed_relocations_undecoded")
    return values, incomplete


def defined_symbol_relocation_map(parsed_obj) -> dict[int, int]:
    """``{slot address: target VA}`` from absolute relocations whose symbol
    is *defined in this object* (fbjni's merged tables).

    fbjni's ``makeNativeMethod`` emits ``{name, kDescriptor, &call}`` where
    the signature and fnPtr words name preemptible weak dynsym symbols -
    ``facebook::jni::jmethod_traits<F>::kDescriptor`` (an OBJECT in
    ``.rodata``) and ``MethodWrapper<...>::call`` /
    ``FunctionWrapperWithJniEntryPoint<...>::call`` (FUNCs) - so the linker
    keeps ``R_*_ABS*`` against the symbol instead of folding the word to
    ``R_*_RELATIVE``. The target is the symbol's value
    plus a RELA addend; REL forms (arm32) keep theirs in the stored word.
    Imported symbols (section index 0) have no link-time value and are
    ignored.
    """
    values: dict[int, int] = {}
    relocations = []
    with contextlib.suppress(Exception):
        relocations = list(parsed_obj.relocations)
    for relocation in relocations:
        if "RELATIVE" in str(getattr(relocation, "type", "")):
            continue
        symbol = None
        with contextlib.suppress(Exception):
            symbol = relocation.symbol
        if symbol is None:
            continue
        try:
            value = int(symbol.value or 0)
            shndx = int(symbol.shndx or 0)
        except (AttributeError, RuntimeError, TypeError, ValueError):
            continue
        if not value or not shndx:
            continue
        addend = 0
        with contextlib.suppress(AttributeError, TypeError, ValueError):
            if relocation.is_rela:
                addend = int(relocation.addend or 0)
        values[int(relocation.address)] = value + addend
    return values


def recover_register_natives_tables(
    parsed_obj, function_starts: set[int], addr_to_name: dict[int, str]
) -> dict | None:
    """Recover ``JNINativeMethod`` tables from ``.data.rel.ro``/``.data``.

    A table is an array of ``{const char *name, const char *signature,
    void *fnPtr}`` whose three pointers are linker-relocated: R_*_RELATIVE
    (RELR, packed), or - fbjni's ``makeNativeMethod`` shape - an
    absolute relocation against the preemptible weak dynsym symbols the
    macro names (``jmethod_traits<F>::kDescriptor`` for the signature,
    ``MethodWrapper<...>::call`` for the fnPtr), which the linker cannot
    fold to RELATIVE. A triple is accepted only when all three hold:
    ``name`` is a Java identifier, ``signature`` matches the JNI
    method-signature grammar, and ``fnPtr`` lands on a function start in
    an executable section (the Thumb bit is allowed on arm32). The class
    stays unset: it lives in the ``FindClass`` call next to
    ``RegisterNatives``, which needs disassembly. Where relocations
    cannot be decoded the scan says so; it never guesses an entry.
    """
    reloc_map, incomplete = relative_relocation_map(parsed_obj)
    for slot, target in defined_symbol_relocation_map(parsed_obj).items():
        reloc_map.setdefault(slot, target)
    if not reloc_map:
        return None
    try:
        word_size = 8 if int(parsed_obj.header.identity[4]) == 2 else 4
    except (AttributeError, IndexError, TypeError):
        word_size = 8
    exec_ranges: list[tuple[int, int]] = []
    with contextlib.suppress(Exception):
        for section in parsed_obj.sections:
            flags = getattr(section, "flags", 0)
            if int(flags) & SHF_EXECINSTR:
                start = int(section.virtual_address)
                exec_ranges.append((start, start + int(section.size)))
    if not exec_ranges:
        return None
    tables: list[dict] = []
    for section in parsed_obj.sections:
        name = getattr(section, "name", "") or ""
        if name not in (".data.rel.ro", ".data"):
            continue
        start = int(section.virtual_address)
        size = int(section.size)
        stride = 3 * word_size
        run: list[dict] = []
        run_address: int | None = None
        slot = start
        while slot + stride <= start + size:
            name_ptr = reloc_map.get(slot)
            sig_ptr = reloc_map.get(slot + word_size)
            fn_ptr = reloc_map.get(slot + 2 * word_size)
            entry = None
            if name_ptr and sig_ptr and fn_ptr:
                method_name = _read_cstring(parsed_obj, name_ptr)
                signature = _read_cstring(parsed_obj, sig_ptr)
                target = fn_ptr & ~1
                if (
                    method_name
                    and _JAVA_IDENTIFIER_RE.match(method_name)
                    and signature
                    and _valid_method_signature(signature)
                    and target in function_starts
                    and any(lo <= target < hi for lo, hi in exec_ranges)
                ):
                    entry = {
                        "name": method_name,
                        "signature": signature,
                        "fn_addr": hex(target),
                        "thumb": bool(fn_ptr & 1),
                        # The triple's own slot: the FindClass confirmer
                        # maps registrations to address ranges, and the
                        # join places each entry in one.
                        "slot": hex(slot),
                    }
                    if fn_name := addr_to_name.get(target):
                        entry["fn_name"] = fn_name
            if entry is not None:
                # An accepted triple consumes its three words; the next
                # candidate is the following triple, so one table's
                # signature/function words cannot look like (and break) a
                # run of their own.
                if run and slot == run_address + len(run) * stride:
                    run.append(entry)
                else:
                    if run:
                        tables.append(_table_record(run_address, run))
                    run = [entry]
                    run_address = slot
                slot += stride
            else:
                if run:
                    tables.append(_table_record(run_address, run))
                    run = []
                    run_address = None
                slot += word_size
        if run:
            tables.append(_table_record(run_address, run))
    if not tables:
        return None
    result: dict = {
        "tables": tables,
        "counts": {
            "tables": len(tables),
            "entries": sum(len(t["entries"]) for t in tables),
        },
    }
    if incomplete:
        result["scan_incomplete"] = incomplete
    return result


def _table_record(address: int | None, entries: list[dict]) -> dict:
    record = {"count": len(entries), "entries": entries}
    if address is not None:
        record["address"] = hex(address)
    return record


def attach_register_natives_tables(metadata: dict, parsed_obj) -> None:
    """Attach the recovered tables to ``metadata["android"]["jni"]``.

    Runs after function discovery so the ``fnPtr`` validation sees every
    start - symbols, exports and the unwind-table discoveries stripped
    builds live on. The ``jni`` block exists already whenever the library
    has a static surface or a lifecycle hook; a table-only library gains
    one here.
    """
    if not metadata.get("is_targeting_android"):
        return
    function_starts: set[int] = set()
    addr_to_name: dict[int, str] = {}
    for key in ("functions", "dynamic_symbols", "symtab_symbols", "ctor_functions"):
        for entry in metadata.get(key) or []:
            if not isinstance(entry, dict) or entry.get("is_imported"):
                continue
            if not (entry.get("is_function") or entry.get("type") == "FUNC"):
                continue
            with contextlib.suppress(TypeError, ValueError):
                address = int(entry.get("value") or entry.get("address"), 16) & ~1
                function_starts.add(address)
                if entry.get("name"):
                    addr_to_name.setdefault(address, entry["name"])
    for discovered in metadata.get("discovered_functions") or []:
        with contextlib.suppress(TypeError, ValueError):
            function_starts.add(int(discovered.get("address"), 16) & ~1)
    if not function_starts:
        return
    tables = recover_register_natives_tables(parsed_obj, function_starts, addr_to_name)
    if tables is None:
        return
    android = metadata.setdefault("android", {})
    jni_block = android.setdefault(
        "jni",
        {
            "static_methods": [],
            "on_load": None,
            "on_unload": None,
            "counts": {"java_exports": 0, "decoded": 0, "decode_errors": 0},
        },
    )
    jni_block["register_natives"] = tables


# ------------------------------------------- the dex->native edges


def extend_app_callgraph_with_jni(app_callgraph: dict, join: dict, native_units: list) -> dict:
    """Add the JNI edges (and the native side) to an app's dex callgraph.

    ``native_units`` is ``[{abi, library, callgraph}, ...]`` - the
    disassembled apk-so-member callgraphs (--disassemble only; without
    disassembly there is no native side and no edge is drawn, the join
    stays a fact). Every native node merges in under a
    ``<library>@<abi>:`` namespace so one graph can carry several ABIs'
    builds of the same library, and each bound dex native declaration
    gains an edge to its implementation node - ``jni_static`` for a
    decoded export, ``jni_dynamic`` for a recovered RegisterNatives
    entry. An edge is added only where both nodes exist; a missing dex
    node (a declaration the dex callgraph never materialized) or a
    missing native node is skipped, never invented.
    """
    if not isinstance(app_callgraph, dict) or not native_units:
        return app_callgraph
    nodes = list(app_callgraph.get("nodes") or [])
    edges: list[dict] = list(app_callgraph.get("edges") or [])
    externals: list[dict] = list(app_callgraph.get("external") or [])
    # dex node ids by exact descriptor name; native nodes by (lib, abi, int addr)
    dex_ids_by_name: dict[str, list[str]] = {}
    for node in nodes:
        name = node.get("name")
        if isinstance(name, str) and name:
            dex_ids_by_name.setdefault(name, []).append(node.get("id"))
    native_addr_ids: dict[tuple[str, str, int], str] = {}
    native_name_ids: dict[tuple[str, str, str], str] = {}
    for unit in native_units:
        abi = unit.get("abi") or ""
        library = unit.get("library") or ""
        namespace = f"{library}@{abi}"
        member_graph = unit.get("callgraph") or {}
        local_ids: dict[int, str] = {}
        for node in member_graph.get("nodes") or []:
            merged = {
                "id": f"{namespace}:{node.get('id')}",
                "key": f"{namespace}!{node.get('key')}",
                "name": node.get("name"),
                "address": node.get("address"),
                "aliases": node.get("aliases") or [],
                "library": library,
                "abi": abi,
            }
            nodes.append(merged)
            with contextlib.suppress(TypeError, ValueError):
                local_ids[int(node.get("id"))] = merged["id"]
            address = node.get("address")
            with contextlib.suppress(TypeError, ValueError):
                native_addr_ids[(library, abi, int(address, 16))] = merged["id"]
            if node.get("name"):
                native_name_ids[(library, abi, str(node["name"]))] = merged["id"]
        for edge in member_graph.get("edges") or []:
            src, dst = edge.get("src"), edge.get("dst")
            if src in local_ids and dst in local_ids:
                merged_edge = dict(edge)
                merged_edge["src"] = local_ids[src]
                merged_edge["dst"] = local_ids[dst]
                edges.append(merged_edge)
        # The unresolved calls out of the native side (PLT thunks, indirect
        # hints) ride along so a path can leave the JNI function the way it
        # leaves the standalone native callgraph.
        for edge in member_graph.get("external") or []:
            if edge.get("src") in local_ids:
                merged_external = dict(edge)
                merged_external["src"] = local_ids[edge["src"]]
                externals.append(merged_external)
    jni_edges: list[dict] = []
    for abi, abi_join in (join.get("per_abi") or {}).items():
        for entry in abi_join.get("bound") or []:
            kind, target_addr = "jni_static", entry.get("fn_addr")
            self_check = entry.get("symbol")
            for dex_id in dex_ids_by_name.get(entry.get("node_name") or "", []):
                native_id = _native_node_id(
                    native_addr_ids,
                    native_name_ids,
                    entry.get("library"),
                    abi,
                    target_addr,
                    self_check,
                )
                if native_id:
                    jni_edges.append({"src": dex_id, "dst": native_id, "kind": kind, "count": 1})
        for entry in abi_join.get("bound_dynamic") or []:
            for dex_id in dex_ids_by_name.get(entry.get("node_name") or "", []):
                native_id = _native_node_id(
                    native_addr_ids,
                    native_name_ids,
                    entry.get("library"),
                    abi,
                    entry.get("fn_addr"),
                    None,
                )
                if native_id:
                    jni_edges.append(
                        {"src": dex_id, "dst": native_id, "kind": "jni_dynamic", "count": 1}
                    )
    if not jni_edges:
        return app_callgraph
    edges.extend(jni_edges)
    result = dict(app_callgraph)
    result["nodes"] = nodes
    result["edges"] = edges
    if externals:
        result["external"] = externals
    result["jni_edge_count"] = len(jni_edges)
    return result


def _native_node_id(
    addr_ids: dict, name_ids: dict, library: str | None, abi: str, address, symbol
) -> str | None:
    """The merged native node id: address first, the export symbol's name
    as the fallback (an address the callgraph could not carry)."""
    if not library:
        return None
    with contextlib.suppress(TypeError, ValueError):
        value = int(address, 16)
        # An arm32 Thumb export carries bit 0; the node address does not.
        for candidate in (value, value & ~1):
            if node_id := addr_ids.get((library, abi, candidate)):
                return node_id
    if symbol:
        return name_ids.get((library, abi, str(symbol)))
    return None
