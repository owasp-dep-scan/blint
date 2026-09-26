"""JNI surface facts for Android native libraries (A5).

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
live here too: F1 recovers ``JNINativeMethod`` tables from relocations,
E2 joins dex ``native`` methods to both surfaces.
"""

from __future__ import annotations

import contextlib
import re

import lief

from blint.logger import LOG

# Escapes per the JNI spec table (Java SE 24). The reverse mapping is
# positional: _1 _, _2 ;, _3 [, _0wxyz U+wxyz (lowercase hex).
_ESCAPES = {"1": "_", "2": ";", "3": "["}
_HEX4_RE = re.compile(r"^[0-9a-f]{4}$")
_DESCRIPTOR_START = "L[BCSIJFDZ"

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
                    }
                )
        except (AttributeError, RuntimeError, TypeError):
            continue
    if not methods:
        return {"natives": natives, "load_library": load_library}
    from blint.lib.dalvik import disassemble_method
    from blint.lib.dalvik_semantics import is_invoke

    try:
        from blint.lib.dalvik import DexPools

        pools = DexPools.from_metadata(dex_metadata)
    except (AttributeError, TypeError, ValueError):
        pools = None
    for method in methods:
        bytecode = getattr(method, "bytecode", None)
        if not bytecode or pools is None:
            continue
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
            bound.append({**native, "class": cls, "symbol": chosen["symbol"]})
        else:
            unbound.append({**native, "class": cls})
    undeclared = [entry for entry in static_methods if entry["symbol"] not in used]
    return {"bound": bound, "unbound_dex_natives": unbound, "undeclared_exports": undeclared}


# ---------------------------------------------------- the app-level summary

# Listing bound for the exported summary, the same shape of cap the other
# app summaries use (a listing bound only; no rule reads these lists).
JOIN_LISTING_CAP = 256


def _join_abi_lists(
    natives: list[dict], surfaces: dict[str, dict | None], lib_abis: dict[str, set[str]], abi: str
) -> dict:
    """One ABI's join across every library that ships in it.

    A dex declaration binds at most once (first library in name order);
    what no library answers is unbound, and each library's unclaimed
    exports are its undeclared list. Counts reflect the full sets; the
    lists themselves are capped at ``JOIN_LISTING_CAP`` with a
    ``truncated`` flag.
    """
    bound: list[dict] = []
    unbound: list[dict] = []
    undeclared: list[dict] = []
    answered: set[tuple[str, str, str]] = set()
    for name in sorted(lib_abis):
        if abi not in lib_abis[name]:
            continue
        result = join_static(natives, surfaces.get(name))
        for entry in result["bound"]:
            key = (entry["class"], entry["name"], entry["descriptor"])
            if key not in answered:
                answered.add(key)
                bound.append({**entry, "abi": abi, "library": name})
        undeclared.extend(
            {**entry, "abi": abi, "library": name} for entry in result["undeclared_exports"]
        )
    for native_entry in natives:
        key = (
            _dotted_class(native_entry["class"]),
            native_entry["name"],
            native_entry["descriptor"],
        )
        if key not in answered:
            unbound.append({**native_entry, "class": key[0], "abi": abi})
    result = {
        "counts": {
            "libraries": sum(1 for name in lib_abis if abi in lib_abis[name]),
            "bound": len(bound),
            "unbound_dex_natives": len(unbound),
            "undeclared_exports": len(undeclared),
        },
        "bound": bound[:JOIN_LISTING_CAP],
        "unbound_dex_natives": unbound[:JOIN_LISTING_CAP],
        "undeclared_exports": undeclared[:JOIN_LISTING_CAP],
    }
    for key_list, full in (
        ("bound", bound),
        ("unbound_dex_natives", unbound),
        ("undeclared_exports", undeclared),
    ):
        if len(full) > JOIN_LISTING_CAP:
            result[f"{key_list}_truncated"] = True
    return result


def build_jni_join_summary(app_file: str, native: dict) -> dict | None:
    """The app-level dex <-> native static join (A5.2 E2).

    Per ABI (ground rule 36: one result per ``(abi, library)``, never a
    silent first-or-best), every dex ``native`` declaration is bound to the
    library whose decoded exports implement it; what no library in that ABI
    answers is reported as unbound (likely dynamic registration, another
    library, or obfuscation), and every export no dex declares is reported
    per library. ``System.loadLibrary`` call sites map to ``lib<name>.so``
    members. Bounded: counts always, the first
    ``JOIN_LISTING_CAP`` entries of each list, ``truncated`` flags beside.
    """
    from blint.lib.android import _iter_app_dex_files
    from blint.lib.android_native import LibraryReader
    from blint.lib.binary import parse_dex
    from blint.lib.binary_elf import parse_symbols

    natives: list[dict] = []
    load_library: list[dict] = []
    try:
        for adex, _ in _iter_app_dex_files(app_file):
            facts = collect_dex_native_facts(parse_dex(adex))
            natives.extend(facts["natives"])
            load_library.extend(facts["load_library"])
    except Exception as exc:  # a malformed app must not abort the analysis
        LOG.debug(f"jni join: dex facts failed for {app_file}: {exc}")
        return None
    if not natives and not load_library:
        return None

    # One light parse per distinct library (the model dedupes by content);
    # the join needs only the dynamic-symbol surface, not full metadata.
    surfaces: dict[str, dict | None] = {}
    abis: set[str] = set()
    lib_abis: dict[str, set[str]] = {}
    try:
        with LibraryReader(app_file) as reader:
            for lib in native.get("libraries") or []:
                name = lib.get("name") or ""
                if not name:
                    continue
                for loc in lib.get("locations") or []:
                    if loc.get("abi"):
                        abis.add(loc["abi"])
                        lib_abis.setdefault(name, set()).add(loc["abi"])
                if name in surfaces or lib.get("not_elf"):
                    continue
                surfaces[name] = None
                data = None
                with contextlib.suppress(Exception):
                    data = reader.read((lib.get("locations") or [])[0])
                if not data:
                    continue
                try:
                    parsed = lief.ELF.parse(list(data))
                    if parsed is None or isinstance(parsed, lief.lief_errors):
                        continue
                    entries, _ = parse_symbols(parsed.dynamic_symbols)
                    surfaces[name] = parse_static_jni_surface(entries)
                except Exception as exc:
                    LOG.debug(f"jni join: surface parse failed for {name}: {exc}")
    except Exception as exc:
        LOG.debug(f"jni join: library surfaces failed for {app_file}: {exc}")

    per_abi: dict[str, dict] = {}
    for abi in sorted(abis):
        per_abi[abi] = _join_abi_lists(natives, surfaces, lib_abis, abi)

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
        "load_library": load_library_summary[:JOIN_LISTING_CAP],
        "per_abi": per_abi,
    }
