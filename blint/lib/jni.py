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

import re

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
