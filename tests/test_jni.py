"""JNI surface facts.

Every binary input is a real NDK r28c build committed under
tests/data/android/ (build commands in a5-jni-fixtures-manifest.json).
The decoder is a pure string function, so its branch tests use symbol
names, not bytes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from blint.lib.binary import parse
from blint.lib.jni import decode_jni_symbol, parse_static_jni_surface

FIXTURES = Path(__file__).parent / "data" / "android"


# ------------------------------------------------------------ the decoder


def test_decode_every_escape() -> None:
    # The liba5 fixture's real symbols, one per mangling rule (JNI spec,
    # "Resolving Native Method Names", Java SE 24).
    assert decode_jni_symbol("Java_com_example_blint_jni_NativeEscapes_plain_1one") == {
        "symbol": "Java_com_example_blint_jni_NativeEscapes_plain_1one",
        "class": "com.example.blint.jni.NativeEscapes",
        "method": "plain_one",
    }
    assert decode_jni_symbol("Java_com_example_blint_jni_NativeEscapes_f__I")["signature"] == "I"
    assert (
        decode_jni_symbol("Java_com_example_blint_jni_NativeEscapes_f__Ljava_lang_String_2")[
            "signature"
        ]
        == "Ljava/lang/String;"
    )
    assert (
        decode_jni_symbol("Java_com_example_blint_jni_NativeEscapes_g___3I")["signature"] == "[I"
    )
    assert decode_jni_symbol("Java_com_example_blint_jni_Nested_00024Inner_deep") == {
        "symbol": "Java_com_example_blint_jni_Nested_00024Inner_deep",
        "class": "com.example.blint.jni.Nested$Inner",
        "method": "deep",
    }
    assert (
        decode_jni_symbol("Java_com_example_blint_native_1lib_Pkg_util")["class"]
        == "com.example.blint.native_lib.Pkg"
    )


def test_decode_spec_examples() -> None:
    # The spec's own ch. 2 examples.
    assert decode_jni_symbol("Java_p_q_r_A_f")["method"] == "f"
    assert decode_jni_symbol("Java_p_q_r_A_f__ILjava_lang_String_2")["signature"] == (
        "ILjava/lang/String;"
    )
    assert decode_jni_symbol("Java_p_q_r_A_f__ILjava_lang_Object_2")["signature"] == (
        "ILjava/lang/Object;"
    )
    # Class B's single native g keeps the short name even though g is
    # overloaded by a non-native declaration.
    assert decode_jni_symbol("Java_p_q_r_B_g") == {
        "symbol": "Java_p_q_r_B_g",
        "class": "p.q.r.B",
        "method": "g",
    }


def test_decode_underscore_method_fallback() -> None:
    # A `__` whose tail is not a descriptor run is the separator plus a
    # _1-escaped leading underscore: class a, method "_".
    assert decode_jni_symbol("Java_a__1") == {
        "symbol": "Java_a__1",
        "class": "a",
        "method": "_",
    }


def test_decode_errors_are_named_never_dropped() -> None:
    assert decode_jni_symbol("Java_onlymethod")["decode_error"] == "no_class_method_separator"
    assert decode_jni_symbol("Java_")["decode_error"] == "no_class_method_separator"
    assert decode_jni_symbol("Java_a_x_0XYZ")["decode_error"].startswith("bad_unicode_escape")
    # Uppercase hex is a spec failure; lowercase is not.
    assert decode_jni_symbol("Java_a_x_000af")["method"] == "x\u00af"
    assert decode_jni_symbol("Java_a_x_000AF")["decode_error"].startswith("bad_unicode_escape")
    # A malformed signature suffix is reported, not guessed.
    assert decode_jni_symbol("Java_a_m__Q")["decode_error"] == "bad_signature_suffix_Q"
    assert decode_jni_symbol("not_java")["decode_error"] == "missing_Java_prefix"


# ------------------------------------------------- the metadata block


def _jni_block(fixture: str) -> dict:
    metadata = parse(str(FIXTURES / fixture))
    return (metadata.get("android") or {}).get("jni")


def test_static_fixture_block() -> None:
    block = _jni_block("liba5_static_arm64-v8a.so")
    assert block is not None
    by_symbol = {entry["symbol"]: entry for entry in block["static_methods"]}
    assert len(by_symbol) == 10
    f_int = by_symbol["Java_com_example_blint_jni_NativeEscapes_f__I"]
    assert (f_int["class"], f_int["method"], f_int["signature"]) == (
        "com.example.blint.jni.NativeEscapes",
        "f",
        "I",
    )
    f_str = by_symbol["Java_com_example_blint_jni_NativeEscapes_f__Ljava_lang_String_2"]
    assert f_str["signature"] == "Ljava/lang/String;"
    assert by_symbol["Java_com_example_blint_jni_NativeEscapes_g___3I"]["signature"] == "[I"
    assert (
        by_symbol["Java_com_example_blint_jni_Nested_00024Inner_deep"]["class"]
        == "com.example.blint.jni.Nested$Inner"
    )
    assert (
        by_symbol["Java_com_example_blint_native_1lib_Pkg_util"]["class"]
        == "com.example.blint.native_lib.Pkg"
    )
    # No signature key at all on the short-name exports.
    assert "signature" not in by_symbol["Java_com_example_blint_jni_Nested_inner"]
    # Lifecycle hooks carry their address from the same parse.
    assert block["on_load"]["symbol"] == "JNI_OnLoad"
    assert block["on_load"]["address"].startswith("0x")
    assert block["on_unload"]["symbol"] == "JNI_OnUnload"
    assert block["counts"] == {"java_exports": 10, "decoded": 10, "decode_errors": 0}


def test_stripped_twin_gives_the_same_block() -> None:
    # The exports are dynamic symbols, so stripping changes nothing.
    assert _jni_block("liba5_static_arm64-v8a.so") == _jni_block(
        "liba5_static_arm64-v8a_stripped.so"
    )

    # For the dynamic library the register_natives tables also match,
    # except that the unstripped twin names the implementation functions.
    def _surface_only(block: dict) -> dict:
        stripped_block = {k: v for k, v in (block or {}).items() if k != "register_natives"}
        for table in ((block or {}).get("register_natives") or {}).get("tables") or []:
            for entry in table.get("entries") or []:
                entry.pop("fn_name", None)
        stripped_block["register_natives"] = (block or {}).get("register_natives")
        return stripped_block

    assert _surface_only(_jni_block("liba5_dynamic_armeabi-v7a.so")) == _surface_only(
        _jni_block("liba5_dynamic_armeabi-v7a_stripped.so")
    )


def test_dynamic_registration_library_has_only_the_hook() -> None:
    block = _jni_block("liba5_dynamic_arm64-v8a.so")
    assert block["static_methods"] == []
    assert block["on_load"]["symbol"] == "JNI_OnLoad"
    assert block["on_unload"] is None
    assert block["counts"]["java_exports"] == 0


def test_block_absent_without_jni_surface() -> None:
    # An Android ELF with no Java_* export and no lifecycle hook has no
    # jni block at all (absent reads as "not present", not "not checked").
    # hello_static is the NDK r28 tier-1 corpus build of hello_static.c
    # (~/sandbox/android-corpus, llvm-nm -D shows 0 JNI
    # symbols); a machine without the corpus skips this half.
    static = (
        Path.home()
        / "sandbox"
        / "android-corpus"
        / "tier1-ndk"
        / "r28"
        / "arm64-v8a"
        / "hello_static"
    )
    if static.exists():
        assert (parse(str(static)).get("android") or {}).get("jni") is None
    # A non-Android ELF has no android block at all.
    metadata = parse(str(FIXTURES.parent / "plain-libc-demo.elf"))
    assert "android" not in metadata


def test_surface_from_symbol_entries_only() -> None:
    # The extractor is a pure function of the dynamic-symbol entries.
    block = parse_static_jni_surface(
        [
            {
                "name": "Java_p_Q_f__I",
                "value": "0x10",
                "is_imported": False,
                "is_function": True,
            },
            {"name": "JNI_OnLoad", "value": "0x20", "is_imported": False, "is_function": True},
            # imports and data symbols never contribute
            {"name": "Java_p_Q_g", "value": "0x0", "is_imported": True, "is_function": True},
            {"name": "Java_p_Q_h", "value": "0x30", "is_imported": False, "is_function": False},
        ]
    )
    assert [entry["symbol"] for entry in block["static_methods"]] == ["Java_p_Q_f__I"]
    assert block["on_load"]["address"] == "0x20"
    assert block["on_unload"] is None
    assert parse_static_jni_surface([]) is None
    assert parse_static_jni_surface(None) is None


# --------------------------------------------------- the join


def test_dex_native_facts_from_the_real_dex() -> None:
    from blint.lib.binary import parse_dex
    from blint.lib.jni import collect_dex_native_facts

    facts = collect_dex_native_facts(parse_dex(str(FIXTURES / "a5-classes.dex")))
    natives = {(n["class"], n["name"], n["descriptor"]) for n in facts["natives"]}
    assert ("Lcom/example/blint/jni/NativeEscapes;", "plain_one", "(I)I") in natives
    assert ("Lcom/example/blint/jni/Nested$Inner;", "deep", "(Ljava/lang/String;)I") in natives
    assert ("Lcom/example/blint/jni/NativeEscapes;", "missingNative", "(I)I") in natives
    assert len(natives) == 15
    # Every loadLibrary site carries its literal and the calling class.
    sites = {(s["class"], s["library"]) for s in facts["load_library"]}
    assert ("Lcom/example/blint/jni/NativeEscapes;", "jnistat") in sites
    assert ("Lcom/example/blint/jni/Nested$Inner;", "jnistat") in sites
    assert ("Lcom/example/blint/jni/Dyn;", "jnidyn") in sites
    assert ("Lcom/example/blint/jni/DynB;", "jnidyn") in sites
    assert ("Lcom/example/blint/native_lib/Pkg;", "jnistat") in sites
    assert len(sites) == 6


def test_join_static_overload_and_signature_policy() -> None:
    from blint.lib.jni import join_static

    natives = [
        {"class": "Lp/Q;", "name": "f", "descriptor": "(I)I"},
        {"class": "Lp/Q;", "name": "f", "descriptor": "(Ljava/lang/String;)I"},
        {"class": "Lp/Q;", "name": "gone", "descriptor": "(I)I"},
    ]
    surface = {
        "static_methods": [
            {"symbol": "Java_p_Q_f__I", "class": "p.Q", "method": "f", "signature": "I"},
            {
                "symbol": "Java_p_Q_f__Ljava_lang_String_2",
                "class": "p.Q",
                "method": "f",
                "signature": "Ljava/lang/String;",
            },
            {"symbol": "Java_p_Q_extra", "class": "p.Q", "method": "extra"},
        ]
    }
    result = join_static(natives, surface)
    assert [(b["name"], b["symbol"]) for b in result["bound"]] == [
        ("f", "Java_p_Q_f__I"),
        ("f", "Java_p_Q_f__Ljava_lang_String_2"),
    ]
    assert [u["name"] for u in result["unbound_dex_natives"]] == ["gone"]
    assert [u["symbol"] for u in result["undeclared_exports"]] == ["Java_p_Q_extra"]
    # A name overloaded in the dex but exported only short-form does not
    # bind by name alone: the signature must disambiguate.
    short_only = {"static_methods": [{"symbol": "Java_p_Q_f", "class": "p.Q", "method": "f"}]}
    result2 = join_static(natives, short_only)
    assert result2["bound"] == []
    assert all(u["name"] == "f" or u["name"] == "gone" for u in result2["unbound_dex_natives"])
    # No surface at all: everything unbound, nothing undeclared.
    result3 = join_static(natives, None)
    assert len(result3["unbound_dex_natives"]) == 3
    assert result3["undeclared_exports"] == []


def test_app_join_summary_matches_the_fixture_source() -> None:
    """Bound equals the fixture's source exactly."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    apk = str(FIXTURES / "a5-jni-arm64-v8a.apk")
    summary = build_jni_join_summary(apk, scan_android_native(apk))
    assert summary["counts"] == {"dex_natives": 15, "load_library_sites": 6, "abis": 1}
    abi = summary["per_abi"]["arm64-v8a"]
    # With table recovery, the five Dyn* declarations bind dynamically and only
    # missingNative stays unbound.
    assert abi["counts"] == {
        "libraries": 2,
        "bound": 9,
        "bound_dynamic": 5,
        "ambiguous_dynamic": 0,
        "unbound_dex_natives": 1,
        "jna_direct": 0,
        "undeclared_exports": 1,
    }
    bound = {(b["class"], b["name"], b["library"], b["symbol"]) for b in abi["bound"]}
    assert (
        "com.example.blint.jni.Nested$Inner",
        "deep",
        "libjnistat.so",
        "Java_com_example_blint_jni_Nested_00024Inner_deep",
    ) in bound
    assert (
        "com.example.blint.native_lib.Pkg",
        "util",
        "libjnistat.so",
        "Java_com_example_blint_native_1lib_Pkg_util",
    ) in bound
    # both f overloads bind to their own __<sig> export
    assert (
        "com.example.blint.jni.NativeEscapes",
        "f",
        "libjnistat.so",
        "Java_com_example_blint_jni_NativeEscapes_f__I",
    ) in bound
    assert (
        "com.example.blint.jni.NativeEscapes",
        "f",
        "libjnistat.so",
        "Java_com_example_blint_jni_NativeEscapes_f__Ljava_lang_String_2",
    ) in bound
    unbound = {(u["class"], u["name"]) for u in abi["unbound_dex_natives"]}
    assert ("com.example.blint.jni.NativeEscapes", "missingNative") in unbound
    dyn_bound = {b["name"]: b for b in abi["bound_dynamic"]}
    assert dyn_bound["dynA1"]["library"] == "libjnidyn.so"
    assert dyn_bound["dynA1"]["fn_addr"] == "0x4934"  # == the unstripped symbol
    assert dyn_bound["dynB2"]["fn_addr"] == "0x4964"
    assert [u["symbol"] for u in abi["undeclared_exports"]] == [
        "Java_com_example_blint_jni_NativeEscapes_orphan"
    ]
    # loadLibrary sites map to the real member names and their ABIs.
    sites = {s["library"]: s for s in summary["load_library"]}
    assert sites["jnistat"]["member"] == "libjnistat.so"
    assert sites["jnistat"]["abis"] == ["arm64-v8a"]
    assert sites["jnidyn"]["member"] == "libjnidyn.so"


def test_dynamic_join_refuses_ambiguous_name_and_signature() -> None:
    """A JNINativeMethod entry has no class, so a (name, signature) pair
    two dex classes declare cannot say which one it implements - fennec's
    disposeNative()V across eleven org.mozilla.gecko classes is the tier-2
    case. Those declarations are listed as ambiguous, never bound; a pair
    unique on both sides still binds."""
    from blint.lib.jni import _join_abi_lists

    natives = [
        {"class": "Lp/A;", "name": "disposeNative", "descriptor": "()V"},
        {"class": "Lp/B;", "name": "disposeNative", "descriptor": "()V"},
        {"class": "Lp/C;", "name": "only", "descriptor": "(I)I"},
    ]
    tables = {
        ("libx.so", "arm64-v8a"): {
            "tables": [
                {
                    "entries": [
                        {"name": "disposeNative", "signature": "()V", "fn_addr": "0x10"},
                        {"name": "only", "signature": "(I)I", "fn_addr": "0x20"},
                    ]
                }
            ]
        }
    }
    result = _join_abi_lists(natives, {}, tables, {"libx.so": {"arm64-v8a"}}, "arm64-v8a")
    assert [(b["class"], b["fn_addr"]) for b in result["bound_dynamic"]] == [("p.C", "0x20")]
    assert {a["class"] for a in result["ambiguous_dynamic"]} == {"p.A", "p.B"}
    assert all(a["table_candidates"] == 1 for a in result["ambiguous_dynamic"])
    assert result["counts"]["ambiguous_dynamic"] == 2
    assert result["unbound_dex_natives"] == []


def test_unique_runtime_entry_binds_only_its_registered_class() -> None:
    """A (name, signature) pair with one declaring class and one entry the
    registrar walk recovered binds as runtime_table only when the walk's
    FindClass class is that declaring class; another class leaves it
    unbound."""
    from blint.lib.jni import _join_abi_lists

    natives = [
        {"class": "Lp/A;", "name": "run", "descriptor": "()V"},
        {"class": "Lp/C;", "name": "other", "descriptor": "(I)V"},
    ]
    runtime = {
        ("libx.so", "x86"): [
            {"class": "p.A", "entries": [{"name": "run", "signature": "()V", "fn_addr": "0x10"}]},
            {
                "class": "p.B",
                "entries": [{"name": "other", "signature": "(I)V", "fn_addr": "0x20"}],
            },
        ]
    }
    result = _join_abi_lists(natives, {}, {}, {"libx.so": {"x86"}}, "x86", {}, runtime)
    assert [
        (b["class"], b["fn_addr"], b.get("confirmed_by")) for b in result["bound_dynamic"]
    ] == [("p.A", "0x10", "runtime_table")]
    assert [u["class"] for u in result["unbound_dex_natives"]] == ["p.C"]


def test_app_join_absent_without_dex_natives() -> None:
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    # The no-dex tier-1 APK has no declarations to join: absent summary.
    apk = str(FIXTURES / "tier1_no_dex.apk")
    assert build_jni_join_summary(apk, scan_android_native(apk)) is None


def test_join_listing_cap_crosses_and_flags() -> None:
    """JOIN_LISTING_CAP (256) truncates the listing, not the counts, and
    flags the truncation - the shape every bounded summary keeps."""
    from blint.lib.jni import JOIN_LISTING_CAP, _join_abi_lists

    natives = [
        {"class": f"Lp/C{i};", "name": "m", "descriptor": "()V"}
        for i in range(JOIN_LISTING_CAP + 5)
    ]
    result = _join_abi_lists(natives, {}, {}, {"libnone.so": {"arm64-v8a"}}, "arm64-v8a")
    assert result["counts"]["unbound_dex_natives"] == JOIN_LISTING_CAP + 5
    assert len(result["unbound_dex_natives"]) == JOIN_LISTING_CAP
    assert result["unbound_dex_natives_truncated"] is True
    # An under-cap join carries no truncation flag.
    small = _join_abi_lists(natives[:3], {}, {}, {"libnone.so": {"arm64-v8a"}}, "arm64-v8a")
    assert "unbound_dex_natives_truncated" not in small
    assert small["counts"]["unbound_dex_natives"] == 3


# ------------------------------------------------ table recovery


def test_register_natives_tables_match_the_fixture_source() -> None:
    """The recovered tables equal the fixture's source -
    names, signatures and fnPtr equal the unstripped symbol address
    (llvm-nm on the twin shows t dyn_a1 0x4934 ... dyn_b2 0x4964)."""
    from blint.lib.binary import parse

    metadata = parse(str(FIXTURES / "liba5_dynamic_arm64-v8a.so"))
    tables = metadata["android"]["jni"]["register_natives"]
    assert tables["counts"] == {"tables": 1, "entries": 5}
    table = tables["tables"][0]
    assert table["count"] == 5
    entries = {e["name"]: e for e in table["entries"]}
    assert set(entries) == {"dynA1", "dynA2", "dynA3", "dynB1", "dynB2"}
    assert entries["dynA1"]["signature"] == "(I)I"
    assert entries["dynA2"]["signature"] == "(Ljava/lang/String;)Ljava/lang/String;"
    assert entries["dynB2"]["signature"] == "(J)I"
    assert entries["dynA1"]["fn_addr"] == "0x4934"
    assert entries["dynA2"]["fn_addr"] == "0x493c"
    assert entries["dynB2"]["fn_addr"] == "0x4964"
    # The unstripped build names the implementation functions.
    assert entries["dynA1"]["fn_name"] == "dyn_a1"
    assert not entries["dynA1"].get("thumb")


def test_register_natives_stripped_twins_recover_the_same_tables() -> None:
    from blint.lib.binary import parse

    for abi in ("arm64-v8a", "armeabi-v7a"):
        plain = parse(str(FIXTURES / f"liba5_dynamic_{abi}.so"))
        stripped = parse(str(FIXTURES / f"liba5_dynamic_{abi}_stripped.so"))
        left = plain["android"]["jni"]["register_natives"]
        right = stripped["android"]["jni"]["register_natives"]
        assert left["counts"] == right["counts"] == {"tables": 1, "entries": 5}
        # Addresses identical; only the unstripped fn_name extras differ.
        for lt, rt in zip(left["tables"], right["tables"]):
            for le, re_ in zip(lt["entries"], rt["entries"]):
                assert (le["name"], le["signature"], le["fn_addr"]) == (
                    re_["name"],
                    re_["signature"],
                    re_["fn_addr"],
                )
                assert "fn_name" in le
                assert "fn_name" not in re_
        # The arm32 table's function pointers carry no Thumb bit in this
        # build (llvm-nm: t dyn_a1 0x15cc, even) and still resolve.
        if abi == "armeabi-v7a":
            first = left["tables"][0]["entries"][0]
            assert first["fn_addr"] == "0x15cc"


def test_register_natives_absent_without_tables() -> None:
    from blint.lib.binary import parse

    for fixture in ("liba5_static_arm64-v8a.so", "liba5_static_arm64-v8a_stripped.so"):
        metadata = parse(str(FIXTURES / fixture))
        assert "register_natives" not in metadata["android"]["jni"]


def test_signature_and_identifier_validators() -> None:
    from blint.lib.jni import (
        _JAVA_IDENTIFIER_RE,
        _valid_method_signature,
    )

    assert _valid_method_signature("()V")
    assert _valid_method_signature("(I)I")
    assert _valid_method_signature("(ILjava/lang/String;)[I")
    assert _valid_method_signature("([J)V")
    assert not _valid_method_signature("(I)")  # missing return
    assert not _valid_method_signature("I")  # missing parens
    assert not _valid_method_signature("(Q)I")  # not a descriptor letter
    assert not _valid_method_signature("(V)I")  # void parameter
    assert not _valid_method_signature("(Ljava/lang/String;)V I")  # two returns
    assert not _valid_method_signature("(I)II")  # two return descriptors
    assert _JAVA_IDENTIFIER_RE.match("dynA1")
    assert _JAVA_IDENTIFIER_RE.match("_private")
    assert not _JAVA_IDENTIFIER_RE.match("1bad")
    assert not _JAVA_IDENTIFIER_RE.match("has-dash")
    assert not _JAVA_IDENTIFIER_RE.match("with space")


# --------------------------------------------- the callgraph edge


def test_node_name_is_the_pools_own_rendering() -> None:
    """The join records each native's dex callgraph node name from
    DexPools._render_method - the same function that builds the graph's
    names - never a re-derived string (this LIEF renders Z as `bool`,
    not `boolean`; a synthesized table missed that, caught on the
    corpus). A boolean-returning native is declared in the fixture to pin
    the Z case."""
    from blint.lib.binary import parse_dex
    from blint.lib.dalvik import DexPools
    from blint.lib.dalvik_callgraph import build_callgraph
    from blint.lib.jni import collect_dex_native_facts

    md = parse_dex(str(FIXTURES / "a5-classes.dex"))
    facts = collect_dex_native_facts(md)
    by_name = {n["name"]: n for n in facts["natives"]}
    # The boolean-returning native renders bool, not boolean.
    assert by_name["flag"]["descriptor"] == "(Z)Z"
    assert by_name["flag"]["node_name"].endswith("->flag(bool)bool")
    # Every invoked native's node_name is exactly a name the dex callgraph
    # emits; missingNative is declared but never invoked, so the graph has
    # no node for it and the edge must not be drawn (never invent a node).
    graph = build_callgraph(md)
    node_names = {n["name"] for n in graph.get("nodes") or []}
    for native in facts["natives"]:
        if native["name"] == "missingNative":
            assert native["node_name"] not in node_names
        else:
            assert native["node_name"] in node_names, native["node_name"]
    # The rendering itself matches DexPools for the same method object.
    methods = {DexPools._render_method(m): m for m in md.get("methods") or []}
    assert by_name["dynA1"]["node_name"] in methods


def test_extend_app_callgraph_never_invents_nodes() -> None:
    from blint.lib.jni import extend_app_callgraph_with_jni

    graph = {"nodes": [{"id": "0:1", "name": "Lp/Q;->m(int)int"}], "edges": []}
    join = {
        "per_abi": {
            "arm64-v8a": {
                "bound": [
                    {
                        "class": "p.Q",
                        "name": "m",
                        "descriptor": "(int)int",
                        "library": "libx.so",
                        "fn_addr": "0x10",
                        "symbol": "Java_p_Q_m",
                    }
                ],
                "bound_dynamic": [],
            }
        }
    }
    # No native side (--disassemble off): unchanged, no edge, no node.
    assert extend_app_callgraph_with_jni(graph, join, []) == graph
    # A native side whose callgraph lacks the target address: the dex node
    # exists but the native one does not - no edge, and the graph only
    # gains the merged native nodes, never a fabricated one.
    native_units = [
        {
            "abi": "arm64-v8a",
            "library": "libx.so",
            "callgraph": {
                "nodes": [{"id": 0, "key": "0x8::other", "name": "other", "address": "0x8"}],
                "edges": [],
            },
        }
    ]
    extended = extend_app_callgraph_with_jni(graph, join, native_units)
    assert "jni_edge_count" not in extended
    assert extended is graph
    # A dex declaration with no dex node: no edge even though the native
    # node exists.
    graph2 = {"nodes": [{"id": "0:1", "name": "Lp/R;->other()void"}], "edges": []}
    native_units2 = [
        {
            "abi": "arm64-v8a",
            "library": "libx.so",
            "callgraph": {
                "nodes": [
                    {"id": 0, "key": "0x10::Java_p_Q_m", "name": "Java_p_Q_m", "address": "0x10"}
                ],
                "edges": [],
            },
        }
    ]
    assert extend_app_callgraph_with_jni(graph2, join, native_units2) is graph2


def test_extend_app_callgraph_draws_both_edge_kinds() -> None:
    from blint.lib.jni import extend_app_callgraph_with_jni

    graph = {
        "nodes": [
            {"id": "0:3", "name": "Lp/Q;->m(int)int"},
            {"id": "0:4", "name": "Lp/Q;->d(long)int"},
        ],
        "edges": [],
    }
    join = {
        "per_abi": {
            "arm64-v8a": {
                "bound": [
                    {
                        "class": "p.Q",
                        "name": "m",
                        "descriptor": "(int)int",
                        "node_name": "Lp/Q;->m(int)int",
                        "library": "libx.so",
                        "fn_addr": "0x1000",
                        "symbol": "Java_p_Q_m",
                    }
                ],
                "bound_dynamic": [
                    {
                        "class": "p.Q",
                        "name": "d",
                        "descriptor": "(long)int",
                        "node_name": "Lp/Q;->d(long)int",
                        "library": "libx.so",
                        "fn_addr": "0x2000",
                    }
                ],
            }
        }
    }
    native_units = [
        {
            "abi": "arm64-v8a",
            "library": "libx.so",
            "callgraph": {
                "nodes": [
                    {
                        "id": 0,
                        "key": "0x1000::Java_p_Q_m",
                        "name": "Java_p_Q_m",
                        "address": "0x1000",
                    },
                    {"id": 1, "key": "0x2000::d_impl", "name": "d_impl", "address": "0x2000"},
                ],
                "edges": [],
                "external": [
                    {"src": 0, "target": "#28", "count": 1, "reason": "address_space_miss"}
                ],
            },
        }
    ]
    out = extend_app_callgraph_with_jni(graph, join, native_units)
    assert out["jni_edge_count"] == 2
    kinds = {
        (e["src"], e["kind"]) for e in out["edges"] if str(e.get("kind", "")).startswith("jni")
    }
    assert kinds == {("0:3", "jni_static"), ("0:4", "jni_dynamic")}
    # The native external edge rides along, namespaced to the merged node.
    assert any(
        e["src"] == "libx.so@arm64-v8a:0" and e["target"] == "#28"
        for e in out.get("external") or []
    )


def test_native_node_lookup_clears_thumb_bit_and_falls_back_to_name() -> None:
    """An arm32 Thumb export's dynsym value carries bit 0 while the
    callgraph node address does not; and an address that is not a node
    still resolves through the export symbol's node name."""
    from blint.lib.jni import _native_node_id

    addr_ids = {("libx.so", "armeabi-v7a", 0x1000): "n0"}
    name_ids = {("libx.so", "armeabi-v7a", "Java_p_Q_m"): "n1"}
    assert _native_node_id(addr_ids, name_ids, "libx.so", "armeabi-v7a", "0x1001", None) == "n0"
    assert (
        _native_node_id(addr_ids, name_ids, "libx.so", "armeabi-v7a", "0x2000", "Java_p_Q_m")
        == "n1"
    )
    assert _native_node_id(addr_ids, name_ids, "libx.so", "armeabi-v7a", "0x2000", None) is None


def _nyxstone_available() -> bool:
    try:
        from blint.lib.disassembler import NYXSTONE_AVAILABLE

        return NYXSTONE_AVAILABLE
    except ImportError:
        return False


@pytest.mark.skipif(not _nyxstone_available(), reason="nyxstone not installed")
def test_r1_end_to_end_path_java_to_libc() -> None:
    """The end-to-end demo: a Java method -> its native declaration -> the JNI
    function -> the imported libc call, one connected path in the app
    callgraph, built exactly the way _process_android_app builds it."""
    import tempfile

    from blint.lib.android import analyze_android_app
    from blint.lib.android_native import LibraryReader, scan_android_native
    from blint.lib.binary import parse
    from blint.lib.jni import build_jni_join_summary, extend_app_callgraph_with_jni
    from blint.lib.runners import _materialize_apk_member

    apk = str(FIXTURES / "a5-jni-arm64-v8a.apk")
    native = scan_android_native(apk)
    join = build_jni_join_summary(apk, native)
    units = []
    with tempfile.TemporaryDirectory(prefix="jni_path_") as tmp, LibraryReader(apk) as reader:
        for lib in native["libraries"]:
            loc = next((x for x in lib["locations"] if x["abi"] == "arm64-v8a"), None)
            if not loc:
                continue
            member = parse(_materialize_apk_member(tmp, reader, loc), disassemble=True)
            units.append(
                {"abi": "arm64-v8a", "library": lib["name"], "callgraph": member.get("callgraph")}
            )
    app = analyze_android_app(apk, build_cg=True)
    graph = extend_app_callgraph_with_jni(app["callgraph"], join, units)

    # The jni edge count equals bound + bound_dynamic.
    abi_join = join["per_abi"]["arm64-v8a"]
    assert (
        graph["jni_edge_count"]
        == abi_join["counts"]["bound"] + abi_join["counts"]["bound_dynamic"]
    )
    nodes_by_id = {n["id"]: n for n in graph["nodes"]}
    ids_by_name: dict[str, list] = {}
    for node in graph["nodes"]:
        ids_by_name.setdefault(node["name"], []).append(node["id"])

    # Hop 1: the Java caller invokes the native declaration.
    caller = ids_by_name["Lcom/example/blint/jni/NativeEscapes;->callThem()int"][0]
    decl = ids_by_name["Lcom/example/blint/jni/NativeEscapes;->libcCall(int)int"][0]
    assert any(e["src"] == caller and e["dst"] == decl for e in graph["edges"])
    # Hop 2: the declaration -> the JNI function (jni_static).
    jni_edge = next(
        e for e in graph["edges"] if e["src"] == decl and e.get("kind") == "jni_static"
    )
    jni_node = nodes_by_id[jni_edge["dst"]]
    assert jni_node["library"] == "libjnistat.so"
    assert jni_node["name"] == "Java_com_example_blint_jni_NativeEscapes_libcCall"
    # Hop 3: the JNI function -> the imported libc call (the getpid@plt
    # thunk; llvm-objdump on the fixture names target 0x4c60 getpid@plt -
    # blint carries it as the external edge with the raw immediate).
    libc_edges = [e for e in graph.get("external") or [] if e["src"] == jni_edge["dst"]]
    assert libc_edges
    # missingNative: declared but never implemented - no node, no edge.
    assert (
        "Lcom/example/blint/jni/NativeEscapes;->missingNative(int)int" not in ids_by_name
        or not any(
            e.get("kind", "").startswith("jni")
            and e["src"]
            in ids_by_name["Lcom/example/blint/jni/NativeEscapes;->missingNative(int)int"]
            for e in graph["edges"]
        )
    )


def _nyxstone_available() -> bool:
    try:
        from blint.lib.disassembler import NYXSTONE_AVAILABLE

        return NYXSTONE_AVAILABLE
    except Exception:
        return False


# -------------------------------------------- fbjni's merged tables


def _a8_hybrid_tables(fixture: str) -> list[dict]:
    metadata = parse(str(FIXTURES / fixture))
    tables = metadata["android"]["jni"]["register_natives"]
    assert tables is not None, "the fbjni-shape tables must recover"
    return tables["tables"]


@pytest.mark.parametrize(
    "fixture",
    [
        "liba8_hybrid_arm64-v8a.so",
        "liba8_hybrid_armeabi-v7a.so",
        "liba8_hybrid_x86_64.so",
        "liba8_hybrid_x86.so",
    ],
)
def test_fbjni_merged_tables_match_the_fixture_source(fixture: str) -> None:
    """The recovery equals a8_hybrid_tables.cpp's tables.

    The fixture carries the measured fbjni shape: name words R_*_RELATIVE,
    signature + fnPtr words absolute against the preemptible dynsym
    symbols (llvm-readelf -r on the arm64 build: R_AARCH64_ABS64 against
    a8_hyb_sig_*/a8_hyb_*_call). The shape itself is asserted first, so a
    future rebuild that folds the words to RELATIVE cannot turn this test
    vacuous - it fails instead.
    """
    import lief

    parsed = lief.ELF.parse(str(FIXTURES / fixture))
    kinds = {}
    for relocation in parsed.relocations:
        symbol = getattr(relocation, "symbol", None)
        name = symbol.name if symbol is not None and symbol.name else ""
        if name.startswith(
            (
                "a8_hyb_sig_",
                "a8_hyb_decoy_sig",
                "a8_hyb_first",
                "a8_hyb_other",
                "a8_hyb_decoy_words",
            )
        ):
            kinds[name] = str(getattr(relocation, "type", ""))
    assert len(kinds) >= 8
    assert all("RELATIVE" not in kind for kind in kinds.values()), (
        "fixture degraded: the signature/fnPtr words must relocate against "
        f"the dynsym symbols, got {kinds}"
    )

    tables = _a8_hybrid_tables(fixture)
    entries = [e for table in tables for e in table["entries"]]
    assert len(entries) == 5
    by_name_sig = {(e["name"], e["signature"]) for e in entries}
    # a8_hybrid_tables.cpp's source tables, verbatim.
    assert by_name_sig == {
        ("hybInit", "()Lcom/blint/a8/HybridFirst;"),
        ("hybTick", "(J)V"),
        ("hybName", "(Ljava/lang/String;)Ljava/lang/String;"),
        ("hybPair", "(II)I"),
        ("hybTick", "(J)J"),
    }
    # The fnPtr words resolve to the wrapper symbols the tables name.
    named = {e["name"]: e.get("fn_name") for e in entries if e["name"] != "hybTick"}
    assert named["hybInit"] == "a8_hyb_first_init_call"
    assert named["hybName"] == "a8_hyb_first_name_call"
    assert named["hybPair"] == "a8_hyb_other_pair_call"


@pytest.mark.parametrize(
    "abi",
    ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"],
)
def test_fbjni_merged_tables_stripped_twins_recover_the_same(abi: str) -> None:
    """The preemptible symbols live in .dynsym, so the stripped twin keeps
    the same absolute relocations and the same recovery (only the fn_name
    extras differ)."""
    plain = parse(str(FIXTURES / f"liba8_hybrid_{abi}.so"))
    stripped = parse(str(FIXTURES / f"liba8_hybrid_{abi}_stripped.so"))
    left = plain["android"]["jni"]["register_natives"]
    right = stripped["android"]["jni"]["register_natives"]
    # arm64 merges the two source arrays into one run; x86_64 keeps them
    # apart (2 tables). Both twins agree, and the entries are the five
    # source methods either way.
    assert left["counts"] == right["counts"]
    assert left["counts"]["entries"] == 5
    for lt, rt in zip(left["tables"], right["tables"]):
        for le, re_ in zip(lt["entries"], rt["entries"]):
            assert (le["name"], le["signature"], le["fn_addr"]) == (
                re_["name"],
                re_["signature"],
                re_["fn_addr"],
            )


@pytest.mark.parametrize(
    "fixture",
    [
        "liba8_hybrid_arm64-v8a.so",
        "liba8_hybrid_armeabi-v7a_stripped.so",
        "liba8_hybrid_x86_64.so",
        "liba8_hybrid_x86_stripped.so",
    ],
)
def test_fbjni_decoy_triple_is_refused(fixture: str) -> None:
    """The adjacent false shape: a triple whose fnPtr word relocates
    against a defined OBJECT in .rodata (not a function start, not an
    executable section) must never become a table entry."""
    tables = _a8_hybrid_tables(fixture)
    entries = [e for table in tables for e in table["entries"]]
    assert all(e["name"] != "hybDecoy" for e in entries)


@pytest.mark.skipif(
    not _nyxstone_available(), reason="the FindClass confirmer decodes through nyxstone"
)
def test_fbjni_shape_binds_the_dex_declarations() -> None:
    """The join on the a8 APK: the fbjni tables bind HybridFirst and
    HybridOther's declarations, hybMissing stays unbound,
    and of the three-class sharedTick pair exactly the two constant-name
    registrations bind - the runtime-composed third stays ambiguous
    with its candidate count."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    apk = str(FIXTURES / "a8-jni-arm64-v8a.apk")
    # Without --disassemble the confirmer does not run: all three stay ambiguous.
    plain = build_jni_join_summary(apk, scan_android_native(apk))
    assert plain["per_abi"]["arm64-v8a"]["counts"]["ambiguous_dynamic"] == 3
    join = build_jni_join_summary(apk, scan_android_native(apk), confirm_findclass=True)
    per_abi = join["per_abi"]["arm64-v8a"]
    assert per_abi["counts"] == {
        "libraries": 2,
        "bound": 0,
        "bound_dynamic": 10,
        "ambiguous_dynamic": 1,
        "unbound_dex_natives": 1,
        "jna_direct": 0,
        "undeclared_exports": 0,
    }
    bound = {
        (e["class"], e["name"], e["library"], e.get("confirmed_by"))
        for e in per_abi["bound_dynamic"]
    }
    assert bound == {
        ("com.blint.a8.HybridFirst", "hybInit", "liba8hyb.so", None),
        ("com.blint.a8.HybridFirst", "hybTick", "liba8hyb.so", None),
        ("com.blint.a8.HybridFirst", "hybName", "liba8hyb.so", None),
        ("com.blint.a8.HybridOther", "hybPair", "liba8hyb.so", None),
        ("com.blint.a8.HybridOther", "hybTick", "liba8hyb.so", None),
        ("com.blint.a8.AmbigOne", "oneOnly", "liba8amb.so", None),
        ("com.blint.a8.AmbigTwo", "twoOnly", "liba8amb.so", None),
        ("com.blint.a8.AmbigThree", "threeOnly", "liba8amb.so", None),
        # The FindClass confirmer bound these two: each to its own
        # registration range, its own implementation.
        ("com.blint.a8.AmbigOne", "sharedTick", "liba8amb.so", "findclass"),
        ("com.blint.a8.AmbigTwo", "sharedTick", "liba8amb.so", "findclass"),
    }
    confirmed = {
        e["class"]: e["fn_name"] for e in per_abi["bound_dynamic"] if e.get("confirmed_by")
    }
    assert confirmed == {
        "com.blint.a8.AmbigOne": "a8_amb_shared_one",
        "com.blint.a8.AmbigTwo": "a8_amb_shared_two",
    }
    ambiguous = {
        (e["class"], e["name"], e["table_candidates"]) for e in per_abi["ambiguous_dynamic"]
    }
    assert ambiguous == {("com.blint.a8.AmbigThree", "sharedTick", 3)}
    unbound = [(e["class"], e["name"]) for e in per_abi["unbound_dex_natives"]]
    assert unbound == [("com.blint.a8.HybridFirst", "hybMissing")]


@pytest.mark.skipif(
    not _nyxstone_available(), reason="the FindClass confirmer decodes through nyxstone"
)
@pytest.mark.parametrize("abi", ["arm64-v8a", "armeabi-v7a", "x86_64"])
def test_findclass_confirmer_needs_the_callsite_abis(abi: str) -> None:
    """Each call-site ABI's twin of the a8 fixture confirms the sharedTick
    registrations from its own bytes (the armeabi-v7a twin is an ARM-mode
    build; the Thumb twin is tested separately): 10 bound, the composed
    third registration the only residue. Without the confirmer all three
    stay ambiguous."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    plain = build_jni_join_summary(
        str(FIXTURES / f"a8-jni-{abi}.apk"),
        scan_android_native(str(FIXTURES / f"a8-jni-{abi}.apk")),
    )
    assert plain["per_abi"][abi]["counts"]["ambiguous_dynamic"] == 3
    join = build_jni_join_summary(
        str(FIXTURES / f"a8-jni-{abi}.apk"),
        scan_android_native(str(FIXTURES / f"a8-jni-{abi}.apk")),
        confirm_findclass=True,
    )
    per_abi = join["per_abi"][abi]
    assert per_abi["counts"]["bound_dynamic"] == 10
    assert per_abi["counts"]["ambiguous_dynamic"] == 1
    assert {(e["class"], e.get("confirmed_by")) for e in per_abi["bound_dynamic"]} >= {
        ("com.blint.a8.AmbigOne", "findclass"),
        ("com.blint.a8.AmbigTwo", "findclass"),
    }


@pytest.mark.skipif(
    not _nyxstone_available(), reason="the FindClass confirmer decodes through nyxstone"
)
def test_findclass_ranges_are_the_registrations() -> None:
    """The oracle, at the confirmer's own granularity: a8_ambig's
    JNI_OnLoad registers [0, 2) for AmbigOne and [2, 4) for AmbigTwo
    with constant names, and the composed third registration confirms
    nothing - the ranges name exactly the two, entry-exact."""
    import lief

    from blint.lib.jni import recover_register_natives_tables
    from blint.lib.jni_findclass import _function_starts, confirm_table_ranges

    parsed = lief.ELF.parse(str(FIXTURES / "liba8_ambig_arm64-v8a.so"))
    starts = _function_starts(parsed)
    tables = recover_register_natives_tables(parsed, set(starts), starts)
    ranges = confirm_table_ranges(parsed, tables["tables"])
    resolved = sorted((r["begin"], r["end"], r["class"]) for r in ranges)
    assert resolved == [
        (0x8D28, 0x8D58, "com.blint.a8.AmbigOne"),
        (0x8D58, 0x8D88, "com.blint.a8.AmbigTwo"),
    ]


# ----------------------------------------------- the join per (abi, library)


@pytest.mark.skipif(
    not _nyxstone_available(), reason="the FindClass confirmer decodes through nyxstone"
)
def test_findclass_ranges_are_the_registrations_on_arm32() -> None:
    """The arm32 layer's own granularity, both dialects: the a8_ambig v7a
    twin (an ARM-mode build) registers [0, 2) for AmbigOne and [2, 4) for
    AmbigTwo, entry-exact like the arm64 twin, and the a12 Thumb twin of
    the same source resolves the same two ranges."""
    import lief

    from blint.lib.jni import recover_register_natives_tables
    from blint.lib.jni_findclass import _function_starts, confirm_table_ranges

    for library in ("liba8_ambig_armeabi-v7a.so", "liba12split_armeabi-v7a.so"):
        parsed = lief.ELF.parse(str(FIXTURES / library))
        starts = _function_starts(parsed)
        tables = recover_register_natives_tables(parsed, set(starts), starts)
        ranges = confirm_table_ranges(parsed, tables["tables"])
        resolved = sorted((r["begin"], r["end"], r["class"]) for r in ranges)
        table_address = int(tables["tables"][0]["address"], 16)
        assert resolved == [
            (table_address, table_address + 24, "com.blint.a8.AmbigOne")
            if "ambig" in library
            else (table_address, table_address + 24, "com.blint.a9.split.SplitOne"),
            (
                table_address + 24,
                table_address + 48,
                "com.blint.a8.AmbigTwo" if "ambig" in library else "com.blint.a9.split.SplitTwo",
            ),
        ], library


def test_multiabi_join_binds_each_abi_from_its_own_bytes() -> None:
    """One result per (abi, library). The a9 multiabi APK
    carries all four ABIs' own copies of liba8hyb.so, so every bound
    fn_addr must be a function start in that ABI's own member bytes - the
    measured first-location defect (RnHello's v7a rows carried 256
    arm64 addresses) fails this on its own fixture."""
    import zipfile

    import lief

    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary
    from blint.lib.jni_findclass import _function_starts

    apk = str(FIXTURES / "a9-jni-multiabi.apk")
    join = build_jni_join_summary(apk, scan_android_native(apk))
    starts_by_member: dict[str, set[int]] = {}
    with zipfile.ZipFile(apk) as zf:
        for info in zf.infolist():
            parts = info.filename.split("/")
            if len(parts) != 3 or parts[0] != "lib" or not parts[2]:
                continue  # the directory entries carry no bytes
            parsed = lief.ELF.parse(zf.read(info))
            assert parsed is not None, info.filename
            starts_by_member[info.filename] = set(_function_starts(parsed))
    fn_addr_by_abi: dict[str, str] = {}
    for abi, abi_join in sorted(join["per_abi"].items()):
        for entry in abi_join["bound_dynamic"]:
            member = f"lib/{abi}/{entry['library']}"
            assert member in starts_by_member, (member, entry)
            starts = starts_by_member[member]
            address = int(entry["fn_addr"], 16) & ~1
            assert address in starts, (abi, entry["name"], entry["fn_addr"])
            if entry["name"] == "hybInit":
                fn_addr_by_abi[abi] = entry["fn_addr"]
    # Each ABI's copy has its own layout: four different addresses, and
    # the join bound each from its own bytes.
    assert len(fn_addr_by_abi) == 4
    assert len(set(fn_addr_by_abi.values())) == 4


def test_multiabi_join_names_the_missing_library() -> None:
    """A library that does not ship in an ABI answers nothing there:
    liba8amb.so ships in arm64-v8a and x86_64 only, so the 32-bit ABIs
    report its declarations unbound - never bound through another ABI's
    tables - while the 64-bit ABIs bind them from their own copies."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    apk = str(FIXTURES / "a9-jni-multiabi.apk")
    join = build_jni_join_summary(apk, scan_android_native(apk))
    for abi in ("armeabi-v7a", "x86"):
        abi_join = join["per_abi"][abi]
        assert abi_join["counts"]["libraries"] == 1  # liba8hyb.so only
        assert not any(e["library"] == "liba8amb.so" for e in abi_join["bound_dynamic"]), (
            "another ABI's tables stood in for a library this ABI does not ship"
        )
        unbound = {(e["class"], e["name"]) for e in abi_join["unbound_dex_natives"]}
        # the ambig fixture's declarations are the missing library's
        assert ("com.blint.a8.AmbigOne", "oneOnly") in unbound
        assert ("com.blint.a8.AmbigTwo", "sharedTick") in unbound
    for abi in ("arm64-v8a", "x86_64"):
        abi_join = join["per_abi"][abi]
        assert abi_join["counts"]["libraries"] == 2
        assert any(
            e["library"] == "liba8amb.so" and e["class"] == "com.blint.a8.AmbigOne"
            for e in abi_join["bound_dynamic"]
        )


@pytest.mark.skipif(
    not _nyxstone_available(), reason="the FindClass confirmer decodes through nyxstone"
)
def test_multiabi_confirmations_stay_in_their_abi() -> None:
    """The FindClass confirmations are per (library, abi): the multiabi
    APK's 64-bit ABIs confirm their own sharedTick registrations while
    the 32-bit ABIs - whose own copies have no call-site layer, and no
    liba8amb.so at all - carry no confirmation of any kind (measured on
    main: arm64's confirmations repeated into every ABI's rows)."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    apk = str(FIXTURES / "a9-jni-multiabi.apk")
    join = build_jni_join_summary(apk, scan_android_native(apk), confirm_findclass=True)
    for abi in ("arm64-v8a", "x86_64"):
        confirmed = {
            (e["class"], e["name"])
            for e in join["per_abi"][abi]["bound_dynamic"]
            if e.get("confirmed_by") == "findclass"
        }
        assert ("com.blint.a8.AmbigOne", "sharedTick") in confirmed
        assert ("com.blint.a8.AmbigTwo", "sharedTick") in confirmed
    for abi in ("armeabi-v7a", "x86"):
        assert not any(e.get("confirmed_by") for e in join["per_abi"][abi]["bound_dynamic"]), (
            f"a {abi} row carries a confirmation that was not read from {abi} bytes"
        )


# --------------------------------------------- the string-bound entries


@pytest.mark.parametrize(
    "abi",
    ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"],
)
def test_string_bound_entries_split_at_the_read_limit(abi: str) -> None:
    """The recovery's string read refuses a name or signature whose NUL
    sits beyond JNI_STRING_READ_LIMIT (1024) instead of truncating it: a
    truncated signature silently failed validation (RnHello's
    initializeBridge, 325 B) and a truncated name could still match the
    identifier grammar and bind as a wrong string. The a9_long fixture
    crosses both sides: sigUnder's 989-byte descriptor recovers, sigLong's
    1279-byte descriptor and the 1120-char method name do not."""
    from blint.lib.binary import parse
    from blint.lib.jni import JNI_STRING_READ_LIMIT

    assert JNI_STRING_READ_LIMIT == 1024  # the fixture's lengths cross this
    metadata = parse(str(FIXTURES / f"liba9_long_{abi}.so"))
    tables = metadata["android"]["jni"]["register_natives"]
    entries = [e for table in tables["tables"] for e in table["entries"]]
    assert [e["name"] for e in entries] == ["sigUnder"]
    assert len(entries[0]["signature"]) == 989
    # the stripped twin recovers the same entry
    stripped = parse(str(FIXTURES / f"liba9_long_{abi}_stripped.so"))
    stripped_tables = stripped["android"]["jni"]["register_natives"]
    assert [e["name"] for t in stripped_tables["tables"] for e in t["entries"]] == ["sigUnder"]


def test_long_string_declarations_bind_or_stay_unbound() -> None:
    """The join on the a9 fixture: the under-limit entry binds its dex
    declaration; the past-limit signature and the past-limit name stay
    unbound - refused, never bound as a truncated prefix."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    apk = str(FIXTURES / "a9-jni-long.apk")
    join = build_jni_join_summary(apk, scan_android_native(apk))
    assert sorted(join["per_abi"]) == ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]
    for abi_join in join["per_abi"].values():
        bound = {(e["name"], len(e["descriptor"])) for e in abi_join["bound_dynamic"]}
        assert bound == {("sigUnder", 989)}
        unbound = {
            (e["name"][:10], len(e["name"]), len(e["descriptor"]))
            for e in abi_join["unbound_dex_natives"]
        }
        assert unbound == {("sigLong", 7, 1279), ("a9LongName", 1120, 4)}


# --------------------------- argument propagation across the registrar's call


@pytest.mark.skipif(
    not _nyxstone_available(), reason="the FindClass confirmer decodes through nyxstone"
)
@pytest.mark.parametrize("abi", ["arm64-v8a", "armeabi-v7a", "x86_64"])
def test_merged_table_splits_by_carried_registration(abi: str) -> None:
    """The fixture check for the carried argument registers: the a9_split
    fixture's five-entry table is registered piecemeal by three per-class
    registrars that stack-copy their slice and call a per-class helper -
    the helper's RegisterNatives reads (methods, count) from the caller's
    argument registers. SplitOne and SplitTwo's shared declarations bind
    to their own implementations; SplitRt's count is a volatile load, so
    its registration carries no constant and its declaration stays
    ambiguous with all three candidates."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    apk = str(FIXTURES / "a9-jni-split.apk")
    native = scan_android_native(apk)
    # Without --disassemble the confirmer does not run: all three stay
    # ambiguous (a gate added in review, still standing).
    plain = build_jni_join_summary(apk, native)
    assert plain["per_abi"][abi]["counts"]["ambiguous_dynamic"] == 3
    join = build_jni_join_summary(apk, native, confirm_findclass=True)
    per_abi = join["per_abi"][abi]
    assert per_abi["counts"] == {
        "libraries": 1,
        "bound": 0,
        "bound_dynamic": 4,
        "ambiguous_dynamic": 1,
        "unbound_dex_natives": 0,
        "jna_direct": 0,
        "undeclared_exports": 0,
    }
    # the x86_64 twin's dynsym carries parameter lists on these names
    confirmed = {
        e["class"]: e["fn_name"].split("(")[0]
        for e in per_abi["bound_dynamic"]
        if e.get("confirmed_by")
    }
    assert confirmed == {
        "com.blint.a9.split.SplitOne": "a9_split_shared_one",
        "com.blint.a9.split.SplitTwo": "a9_split_shared_two",
    }
    ambiguous = {
        (e["class"], e["name"], e["table_candidates"]) for e in per_abi["ambiguous_dynamic"]
    }
    assert ambiguous == {("com.blint.a9.split.SplitRt", "splitShared", 3)}


@pytest.mark.skipif(
    not _nyxstone_available(), reason="the FindClass confirmer decodes through nyxstone"
)
def test_split_ranges_are_the_registrars_slices() -> None:
    """Entry-exact, at the confirmer's own granularity: the two constant
    registrars cover [T, T+2) and [T+2, T+4); the runtime-count
    registration covers nothing."""
    import lief

    from blint.lib.jni import recover_register_natives_tables
    from blint.lib.jni_findclass import _function_starts, confirm_table_ranges

    parsed = lief.ELF.parse(str(FIXTURES / "liba9_split_arm64-v8a.so"))
    starts = _function_starts(parsed)
    tables = recover_register_natives_tables(parsed, set(starts), starts)
    ranges = confirm_table_ranges(parsed, tables["tables"])
    resolved = sorted((r["begin"], r["end"], r["class"]) for r in ranges)
    table_address = int(tables["tables"][0]["address"], 16)
    assert resolved == [
        (table_address, table_address + 48, "com.blint.a9.split.SplitOne"),
        (table_address + 48, table_address + 96, "com.blint.a9.split.SplitTwo"),
    ]


@pytest.mark.skipif(
    not _nyxstone_available(), reason="the FindClass confirmer decodes through nyxstone"
)
def test_split_fixture_stays_ambiguous_off_the_callsite_abis() -> None:
    """Every ABI's own copy splits the same way (arm64 and x86_64,
    x86 through its i386 layer, armeabi-v7a through its arm32 layer - the
    fixture's v7a build is ARM-mode); the only residue on any ABI is the
    volatile-count registration, which no layer can read."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    apk = str(FIXTURES / "a9-jni-split.apk")
    join = build_jni_join_summary(apk, scan_android_native(apk), confirm_findclass=True)
    for abi in ("arm64-v8a", "x86_64", "x86", "armeabi-v7a"):
        per_abi = join["per_abi"][abi]
        assert per_abi["counts"]["ambiguous_dynamic"] == 1, abi
        confirmed = {
            e["class"].rsplit(".", 1)[-1]
            for e in per_abi["bound_dynamic"]
            if e.get("confirmed_by")
        }
        assert confirmed == {"SplitOne", "SplitTwo"}, abi
        assert [e["class"].rsplit(".", 1)[-1] for e in per_abi["ambiguous_dynamic"]] == ["SplitRt"]


@pytest.mark.skipif(
    not _nyxstone_available(), reason="the FindClass confirmer decodes through nyxstone"
)
def test_split_fixture_splits_in_the_thumb_dialect_too() -> None:
    """The a12 fixture is the a9_split source built with -mthumb (every
    shipped v7a library is Thumb; the earlier v7a fixtures came out
    ARM-mode). The same chain - the staging's pool-pair and NEON slice
    copy, the per-class helper's vtable call reading the carried pair -
    splits exactly like the ARM-mode twin, and the volatile-count
    registration stays ambiguous."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    apk = str(FIXTURES / "a12-jni-split-thumb.apk")
    native = scan_android_native(apk)
    plain = build_jni_join_summary(apk, native)
    assert plain["per_abi"]["armeabi-v7a"]["counts"]["ambiguous_dynamic"] == 3
    join = build_jni_join_summary(apk, native, confirm_findclass=True)
    per_abi = join["per_abi"]["armeabi-v7a"]
    assert per_abi["counts"] == {
        "libraries": 1,
        "bound": 0,
        "bound_dynamic": 4,
        "ambiguous_dynamic": 1,
        "unbound_dex_natives": 0,
        "jna_direct": 0,
        "undeclared_exports": 0,
    }
    confirmed = {
        e["class"].rsplit(".", 1)[-1] for e in per_abi["bound_dynamic"] if e.get("confirmed_by")
    }
    assert confirmed == {"SplitOne", "SplitTwo"}
    assert [e["class"].rsplit(".", 1)[-1] for e in per_abi["ambiguous_dynamic"]] == ["SplitRt"]


# ------------------- the honest 32-bit refusals, pinned per ABI


def _a10_gap_tables(abi: str, stripped: bool = False) -> dict | None:
    import lief

    from blint.lib.jni import recover_register_natives_tables
    from blint.lib.jni_findclass import _function_starts

    suffix = "_stripped" if stripped else ""
    parsed = lief.ELF.parse(str(FIXTURES / f"liba10_gap_{abi}{suffix}.so"))
    starts = _function_starts(parsed)
    return recover_register_natives_tables(parsed, set(starts), starts)


@pytest.mark.parametrize("abi", ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"])
def test_gap_fixture_recovery_and_fates(abi: str) -> None:
    """The a10 gap fixture, per ABI (the two measured causes beside controls that
    must keep binding). plainAdd (constant-initialized table) and weakOnly
    (the fbjni kDescriptor shape: the signature word relocates against a
    weak preemptible OBJECT dynsym, on the REL ABIs too) recover on every
    ABI. nounwindAdd's implementation is a real wrapper compiled without
    unwind tables and hidden: it recovers only on armeabi-v7a, where lld
    backfills an .ARM.exidx CANTUNWIND entry for functions whose object
    has none - on the eh_frame ABIs no start source can verify the fnPtr
    and the triple is refused. smallOnly (the registrar builds the entry
    at run time through a noinline constructor - no static triple) and
    decoyDataFn (fnPtr against a defined OBJECT) never recover."""
    expected = {"plainAdd", "weakOnly"}
    if abi == "armeabi-v7a":
        expected.add("nounwindAdd")
    for stripped in (False, True):
        tables = _a10_gap_tables(abi, stripped)
        entries = {e["name"] for t in tables["tables"] for e in t["entries"]}
        assert entries == expected
        by_name = {e["name"]: e for t in tables["tables"] for e in t["entries"]}
        # the raw dynsym name on the .so path, demangled on the join path
        assert "a10_plain_add" in by_name["plainAdd"]["fn_name"]
        assert "a10_small_impl" in by_name["weakOnly"]["fn_name"]
        assert by_name["weakOnly"]["signature"] == "(I)I"


def test_gap_fixture_join_binds_each_abi_from_its_own_bytes() -> None:
    """The join on the a10 APK: every ABI binds plainAdd and weakOnly and
    leaves smallOnly and decoyDataFn unbound; nounwindAdd binds only on
    armeabi-v7a (its exidx entry). Each ABI's plainAdd fn_addr is its own
    copy's address - no two ABIs share one."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    apk = str(FIXTURES / "a10-jni-gap.apk")
    join = build_jni_join_summary(apk, scan_android_native(apk))
    assert sorted(join["per_abi"]) == ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]
    plain_addrs: dict[str, str] = {}
    for abi, abi_join in join["per_abi"].items():
        bound = {e["name"] for e in abi_join["bound_dynamic"]}
        unbound = {e["name"] for e in abi_join["unbound_dex_natives"]}
        assert bound == {"plainAdd", "weakOnly"} | (
            {"nounwindAdd"} if abi == "armeabi-v7a" else set()
        )
        assert unbound == {"smallOnly", "decoyDataFn"} | (
            set() if abi == "armeabi-v7a" else {"nounwindAdd"}
        )
        assert abi_join["counts"]["ambiguous_dynamic"] == 0
        plain_addrs[abi] = next(
            e["fn_addr"] for e in abi_join["bound_dynamic"] if e["name"] == "plainAdd"
        )
    assert len(set(plain_addrs.values())) == 4


def _llvm_readelf() -> str | None:
    import contextlib
    import shutil
    import subprocess

    for candidate in (
        shutil.which("llvm-readelf"),
        "/opt/homebrew/opt/llvm@18/bin/llvm-readelf",
    ):
        if candidate and Path(candidate).exists():
            with contextlib.suppress(Exception):
                run = subprocess.run([candidate, "--version"], capture_output=True, timeout=30)
                if run.returncode == 0:
                    return candidate
    return None


@pytest.mark.skipif(_llvm_readelf() is None, reason="the fn_addr oracle reads llvm-readelf")
@pytest.mark.parametrize("abi", ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"])
def test_gap_fixture_fn_addrs_pass_the_readelf_oracle(abi: str) -> None:
    """The independent oracle, asserted in the same run: every
    recovered fn_addr is a function start in its own ABI's bytes per
    llvm-readelf - a defined FUNC dynsym symbol, or on armeabi-v7a an
    .ARM.exidx entry (lld's backfilled CANTUNWIND row for nounwindAdd
    makes that ABI's third binding legitimate rather than lucky)."""
    import re
    import subprocess

    readelf = _llvm_readelf()
    path = FIXTURES / f"liba10_gap_{abi}.so"
    out = subprocess.run([readelf, "--dyn-syms", str(path)], capture_output=True, text=True).stdout
    func_starts = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[3] == "FUNC" and parts[6] != "UND":
            func_starts.add(int(parts[1], 16) & ~1)
    if abi == "armeabi-v7a":
        dump = subprocess.run(
            [readelf, "-x", ".ARM.exidx", str(path)], capture_output=True, text=True
        ).stdout
        exidx_starts = set()
        for line in dump.splitlines():
            match = re.match(r"^\s*0x([0-9a-f]+)\s+((?:[0-9a-f]{8}\s+){1,4})", line)
            if not match:
                continue
            base = int(match.group(1), 16)
            groups = match.group(2).split()
            for index, group in enumerate(groups):
                if index % 2:  # word 1 is the unwind model, not a start
                    continue
                word = int.from_bytes(bytes.fromhex(group), "little")
                offset = word & 0x7FFFFFFF
                if word & 0x40000000:  # PREL31 sign bit (bit 30, per the EHABI)
                    offset -= 1 << 31
                exidx_starts.add((base + index * 4 + offset) & ~1)
        func_starts |= exidx_starts
    tables = _a10_gap_tables(abi)
    for table in tables["tables"]:
        for entry in table["entries"]:
            assert int(entry["fn_addr"], 16) in func_starts, (abi, entry["name"], entry["fn_addr"])


# ---------------------------- candidates registered elsewhere


@pytest.mark.skipif(
    not _nyxstone_available(), reason="the FindClass confirmer decodes through nyxstone"
)
@pytest.mark.parametrize("abi", ["arm64-v8a", "x86_64"])
def test_mark_when_every_candidate_is_registered_for_another_class(abi: str) -> None:
    """The a10 nowhere fixture: nwShared is declared by NwBound, NwMissing
    and NwElsewhere, and its one table entry is registered for NwBound with
    a constant count. With --disassemble NwBound binds through the
    confirmer; NwMissing's row - ambiguous, its only candidate covered by
    NwBound's range, its class named by no resolved registration - carries
    candidates_registered_elsewhere. NwElsewhere's identical-looking
    nwShared row does NOT: its own nwMine registration names it. The nwRt
    rows stay plain ambiguous: their candidates sit in no resolved range
    (volatile counts), so the confirmer claims nothing and no mark
    appears."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    apk = str(FIXTURES / "a10-jni-nowhere.apk")
    native = scan_android_native(apk)
    plain = build_jni_join_summary(apk, native)
    assert plain["per_abi"][abi]["counts"]["ambiguous_dynamic"] == 5
    assert not any(
        "candidates_registered_elsewhere" in e for e in plain["per_abi"][abi]["ambiguous_dynamic"]
    )
    join = build_jni_join_summary(apk, native, confirm_findclass=True)
    per_abi = join["per_abi"][abi]
    bound = {(e["class"], e["name"]) for e in per_abi["bound_dynamic"]}
    assert bound == {
        ("com.blint.a10.nowhere.NwBound", "nwShared"),
        # the unique (name, signature) pair binds without the confirmer
        ("com.blint.a10.nowhere.NwElsewhere", "nwMine"),
    }
    ambiguous = {
        (e["class"], e["name"], e.get("candidates_registered_elsewhere", False))
        for e in per_abi["ambiguous_dynamic"]
    }
    assert ambiguous == {
        ("com.blint.a10.nowhere.NwMissing", "nwShared", True),
        ("com.blint.a10.nowhere.NwElsewhere", "nwShared", False),
        ("com.blint.a10.nowhere.NwRtA", "nwRt", False),
        ("com.blint.a10.nowhere.NwRtB", "nwRt", False),
    }


@pytest.mark.skipif(
    not _nyxstone_available(), reason="the FindClass confirmer decodes through nyxstone"
)
def test_no_candidates_mark_without_resolved_ranges() -> None:
    """The mark needs the --disassemble confirmer's resolved ranges: the
    plain join never marks. With the flag on, every ABI has a call-site
    layer, so each resolves
    NwBound's range and leaves the same four-row shape the 64-bit ABIs
    have."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    apk = str(FIXTURES / "a10-jni-nowhere.apk")
    native = scan_android_native(apk)
    plain = build_jni_join_summary(apk, native)
    for abi in ("armeabi-v7a", "x86"):
        assert plain["per_abi"][abi]["counts"]["ambiguous_dynamic"] == 5
        assert not any(
            "candidates_registered_elsewhere" in e
            for e in plain["per_abi"][abi]["ambiguous_dynamic"]
        )
    join = build_jni_join_summary(apk, native, confirm_findclass=True)
    v7a = join["per_abi"]["armeabi-v7a"]
    assert v7a["counts"]["ambiguous_dynamic"] == 4
    marked = {
        (e["class"].rsplit(".", 1)[-1], e.get("candidates_registered_elsewhere", False))
        for e in v7a["ambiguous_dynamic"]
    }
    assert ("NwMissing", True) in marked
    # the i386 layer does not read this fixture's registrar chain (the same
    # pre-existing x86 residue the a8 twin shows), so x86 stays at the
    # plain-ambiguous shape even with the flag
    x86 = join["per_abi"]["x86"]
    assert x86["counts"]["ambiguous_dynamic"] == 5
    assert not any("candidates_registered_elsewhere" in e for e in x86["ambiguous_dynamic"])


# ------------------- tables built at run time


@pytest.mark.skipif(
    not _nyxstone_available(), reason="the runtime-table recovery decodes through nyxstone"
)
@pytest.mark.parametrize("abi", ["x86", "armeabi-v7a"])
def test_runtime_tables_bind_where_the_walk_reads_them(abi: str) -> None:
    """The registrar walk's stores are the only source of the runtime
    entries: the constant-count word-store registrar (RtNative), the
    realigned registrar (RtAligned) and the pair-passing chain (RtPair)
    bind through runtime_table - on x86 (i386) and on
    armeabi-v7a (arm32 in its ARM state; the Thumb twin is the
    fixture below). The volatile-count twin stays ambiguous everywhere,
    and no ABI outside these two carries a runtime_table binding."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    apk = str(FIXTURES / "a11-jni-rt.apk")
    native = scan_android_native(apk)
    join = build_jni_join_summary(apk, native, confirm_findclass=True)
    per_abi = join["per_abi"][abi]
    bound = {
        (e["class"].rsplit(".", 1)[-1], e["name"]): e.get("confirmed_by")
        for e in per_abi["bound_dynamic"]
    }
    expected = {
        ("RtAligned", "rtOne"): "runtime_table",
        ("RtNative", "rtOne"): "runtime_table",
        ("RtNative", "rtShared"): "runtime_table",
        ("RtPair", "rtOne"): "runtime_table",
        ("RtPair", "rtShared"): "runtime_table",
    }
    if abi == "armeabi-v7a":
        # the arm32 confirmer also resolves this fixture's static
        # control, which the i386 layer does not read
        expected[("RtStatic", "rtStaticAdd")] = "findclass"
    assert bound == expected
    ambiguous = {(e["class"].rsplit(".", 1)[-1], e["name"]) for e in per_abi["ambiguous_dynamic"]}
    assert ("RtVolatile", "rtOne") in ambiguous
    assert ("RtVolatile", "rtShared") in ambiguous
    for other in ("arm64-v8a", "x86_64"):
        expectations = {
            "bound_dynamic": 1,
            "ambiguous_dynamic": 1,
            "unbound_dex_natives": 7,
        }
        other_join = join["per_abi"][other]
        assert {k: other_join["counts"][k] for k in expectations} == expectations, other
        assert not any(
            e.get("confirmed_by") == "runtime_table" for e in other_join["bound_dynamic"]
        ), other


@pytest.mark.skipif(
    not _nyxstone_available(), reason="the runtime-table recovery decodes through nyxstone"
)
def test_runtime_tables_bind_in_the_thumb_dialect_too() -> None:
    """The a12 fixture is the a11_rt source built with -mthumb: the same
    registrar shapes (word stores, the realigned frame, the pair-passing
    chain, the volatile refusal) recover identically in the Thumb
    dialect, and the static control confirms through findclass."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    apk = str(FIXTURES / "a12-jni-thumb.apk")
    native = scan_android_native(apk)
    join = build_jni_join_summary(apk, native, confirm_findclass=True)
    per_abi = join["per_abi"]["armeabi-v7a"]
    bound = {
        (e["class"].rsplit(".", 1)[-1], e["name"]): e.get("confirmed_by")
        for e in per_abi["bound_dynamic"]
    }
    assert bound == {
        ("RtAligned", "rtOne"): "runtime_table",
        ("RtNative", "rtOne"): "runtime_table",
        ("RtNative", "rtShared"): "runtime_table",
        ("RtPair", "rtOne"): "runtime_table",
        ("RtPair", "rtShared"): "runtime_table",
        ("RtStatic", "rtStaticAdd"): "findclass",
    }
    ambiguous = {(e["class"].rsplit(".", 1)[-1], e["name"]) for e in per_abi["ambiguous_dynamic"]}
    assert ("RtVolatile", "rtOne") in ambiguous
    assert ("RtVolatile", "rtShared") in ambiguous


@pytest.mark.skipif(
    not _nyxstone_available(), reason="the runtime-table recovery decodes through nyxstone"
)
def test_runtime_tables_need_the_disassemble_flag() -> None:
    """Without --disassemble the runtime recovery never runs: every
    runtime-built row stays unbound exactly as before runtime recovery existed."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    apk = str(FIXTURES / "a11-jni-rt.apk")
    join = build_jni_join_summary(apk, scan_android_native(apk), confirm_findclass=False)
    for abi in ("x86", "armeabi-v7a"):
        per_abi = join["per_abi"][abi]
        assert per_abi["counts"]["bound_dynamic"] == 0, abi
        assert per_abi["counts"]["unbound_dex_natives"] == 7, abi


@pytest.mark.skipif(_llvm_readelf() is None, reason="the fn_addr oracle reads llvm-readelf")
@pytest.mark.skipif(
    not _nyxstone_available(), reason="the runtime-table recovery decodes through nyxstone"
)
@pytest.mark.parametrize("abi", ["x86", "armeabi-v7a"])
def test_runtime_table_fn_addrs_pass_the_start_oracle(abi: str) -> None:
    """Every fn_addr the runtime recovery reports is a function start of
    that ABI copy's own bytes (llvm-readelf dynsym FUNCs plus eh_frame
    FDEs, and .ARM.exidx on armeabi-v7a - never blint's own discovery)."""
    import re
    import subprocess

    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    apk = str(FIXTURES / "a11-jni-rt.apk")
    join = build_jni_join_summary(apk, scan_android_native(apk), confirm_findclass=True)
    per_abi = join["per_abi"][abi]
    readelf = _llvm_readelf()
    library = FIXTURES / f"liba11rt_{abi}.so"
    starts = set()
    out = subprocess.run(
        [readelf, "--dyn-syms", str(library)], capture_output=True, text=True
    ).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[3] == "FUNC" and parts[6] != "UND":
            starts.add(int(parts[1], 16) & ~1)
    objdump = readelf.replace("llvm-readelf", "llvm-objdump")
    frames = subprocess.run(
        [objdump, "--dwarf=frames", str(library)],
        capture_output=True,
        text=True,
    ).stdout
    for match in re.finditer(r"pc=0*([0-9a-f]+)\.{2,3}0*[0-9a-f]+", frames):
        starts.add(int(match.group(1), 16) & ~1)
    if abi == "armeabi-v7a":
        dump = subprocess.run(
            [readelf, "-x", ".ARM.exidx", str(library)], capture_output=True, text=True
        ).stdout
        for line in dump.splitlines():
            match = re.match(r"^\s*0x([0-9a-f]+)\s+((?:[0-9a-f]{8}\s+){1,4})", line)
            if not match:
                continue
            base = int(match.group(1), 16)
            for index, group in enumerate(match.group(2).split()):
                if index % 2:
                    continue
                word = int.from_bytes(bytes.fromhex(group), "little")
                offset = word & 0x7FFFFFFF
                if word & 0x40000000:
                    offset -= 1 << 31
                starts.add((base + index * 4 + offset) & ~1)
    checked = 0
    for entry in per_abi["bound_dynamic"]:
        if entry.get("confirmed_by") != "runtime_table":
            continue
        assert int(entry["fn_addr"], 16) in starts, entry
        checked += 1
    assert checked == 5


@pytest.mark.skipif(
    not _nyxstone_available(), reason="the runtime-table recovery decodes through nyxstone"
)
@pytest.mark.parametrize(
    "apk",
    ["a13-jni-singles.apk", "a13-jni-singles-thumb.apk"],
)
def test_runtime_singles_bind_in_both_dialects(apk: str) -> None:
    """The 32-bit singles' registrar shapes: the lazy class (found only on
    the cold init path below the RegisterNatives call), the sret class
    finder (whose i386 callee pops its hidden result pointer, with the
    caller's re-alignment between the entry stores and the methods lea)
    and the pair-passing chain whose callee makes its own sret call all
    bind through runtime_table on armeabi-v7a (both dialects) and x86.
    The two-class refusal twin stays undecided, and the static control
    keeps binding."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    path = str(FIXTURES / apk)
    join = build_jni_join_summary(path, scan_android_native(path), confirm_findclass=True)
    expected = {
        ("RtLazy", "rtOne"): "runtime_table",
        ("RtPairSret", "rtOne"): "runtime_table",
        ("RtPairSret", "rtShared"): "runtime_table",
        ("RtSret", "rtOne"): "runtime_table",
    }
    for abi in ("armeabi-v7a", "x86"):
        if abi not in join["per_abi"]:
            continue
        per_abi = join["per_abi"][abi]
        bound = {
            (e["class"].rsplit(".", 1)[-1], e["name"]): e.get("confirmed_by")
            for e in per_abi["bound_dynamic"]
        }
        assert bound.pop(("RtControl", "rtStaticAdd")) is None, abi
        assert bound == expected, (apk, abi)
        # the refusal twin: its cold path names two classes, so the call
        # that no class materialization precedes stays unread
        ambiguous = {
            (e["class"].rsplit(".", 1)[-1], e["name"]) for e in per_abi["ambiguous_dynamic"]
        }
        assert ("RtTwo", "rtOne") in ambiguous, (apk, abi)


@pytest.mark.skipif(
    not _nyxstone_available(), reason="the runtime-table recovery decodes through nyxstone"
)
def test_runtime_singles_stay_unbound_off_the_32bit_walks() -> None:
    """No ABI outside the two 32-bit walks carries a runtime_table binding,
    and without --disassemble nothing runtime-built binds anywhere."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    path = str(FIXTURES / "a13-jni-singles.apk")
    native = scan_android_native(path)
    join = build_jni_join_summary(path, native, confirm_findclass=True)
    for abi in ("arm64-v8a", "x86_64"):
        per_abi = join["per_abi"][abi]
        unbound = {
            (e["class"].rsplit(".", 1)[-1], e["name"]) for e in per_abi["unbound_dex_natives"]
        }
        assert ("RtTwo", "rtOne") in unbound, abi
        assert ("RtLazy", "rtOne") in unbound, abi
        assert not any(
            e.get("confirmed_by") == "runtime_table" for e in per_abi["bound_dynamic"]
        ), abi
    plain = build_jni_join_summary(path, native, confirm_findclass=False)
    for abi, per_abi in plain["per_abi"].items():
        assert not any(
            e.get("confirmed_by") == "runtime_table" for e in per_abi["bound_dynamic"]
        ), abi


@pytest.mark.skipif(
    not _nyxstone_available(), reason="the runtime-table recovery decodes through nyxstone"
)
@pytest.mark.parametrize(
    "plain_name,stripped_name,expected",
    [
        (
            "liba13rt_x86.so",
            "liba13rt_x86_stripped.so",
            {"rtOne": "0x1a20", "rtShared": "0x1a30"},
        ),
        # the v7a twin is the -mthumb build: a stripped copy keeps no
        # mapping symbols, and the NDK default (Thumb) is then the only
        # mode evidence - right for this build. The ARM-state build's
        # stripped copy has none either and its statics would decode as
        # Thumb, so it is not a twin this recovery can read.
        (
            "liba13rt_thumb_armeabi-v7a.so",
            "liba13rt_thumb_armeabi-v7a_stripped.so",
            {"rtOne": "0x1698", "rtShared": "0x169c"},
        ),
    ],
)
def test_runtime_singles_stripped_twins_recover_the_same(
    plain_name: str, stripped_name: str, expected: dict
) -> None:
    """The stripped twin recovers the same runtime registrations as the
    unstripped copy: the walk's starts come from the dynsym plus the
    unwind tables, not the symtab."""
    import lief

    from blint.lib.jni_findclass import recover_runtime_tables

    def registrations(path: str) -> set[tuple]:
        parsed = lief.ELF.parse(path)
        return {
            (
                r["class"],
                tuple((e["name"], e["signature"], e["fn_addr"]) for e in r["entries"]),
            )
            for r in recover_runtime_tables(parsed)
        }

    plain = registrations(str(FIXTURES / plain_name))
    stripped = registrations(str(FIXTURES / stripped_name))
    assert (
        plain
        == stripped
        == {
            (
                "com.blint.a13.rt.RtLazy",
                (("rtOne", "(I)I", expected["rtOne"]),),
            ),
            (
                "com.blint.a13.rt.RtPairSret",
                (
                    ("rtOne", "(I)I", expected["rtOne"]),
                    ("rtShared", "(J)J", expected["rtShared"]),
                ),
            ),
            (
                "com.blint.a13.rt.RtSret",
                (("rtOne", "(I)I", expected["rtOne"]),),
            ),
        }
    )


@pytest.mark.skipif(_llvm_readelf() is None, reason="the fn_addr oracle reads llvm-readelf")
@pytest.mark.skipif(
    not _nyxstone_available(), reason="the runtime-table recovery decodes through nyxstone"
)
@pytest.mark.parametrize("abi", ["x86", "armeabi-v7a"])
def test_runtime_singles_fn_addrs_pass_the_start_oracle(abi: str) -> None:
    """Every fn_addr the singles' recovery reports is a function start of
    that ABI copy's own bytes (llvm-readelf dynsym FUNCs plus eh_frame
    FDEs, and .ARM.exidx on armeabi-v7a - never blint's own discovery)."""
    import re
    import subprocess

    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    path = str(FIXTURES / "a13-jni-singles.apk")
    join = build_jni_join_summary(path, scan_android_native(path), confirm_findclass=True)
    per_abi = join["per_abi"][abi]
    library = FIXTURES / f"liba13rt_{abi}.so"
    starts = set()
    readelf = _llvm_readelf()
    out = subprocess.run(
        [readelf, "--dyn-syms", str(library)], capture_output=True, text=True
    ).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[3] == "FUNC" and parts[6] != "UND":
            starts.add(int(parts[1], 16) & ~1)
    objdump = readelf.replace("llvm-readelf", "llvm-objdump")
    frames = subprocess.run(
        [objdump, "--dwarf=frames", str(library)], capture_output=True, text=True
    ).stdout
    for match in re.finditer(r"pc=0*([0-9a-f]+)\.{2,3}0*[0-9a-f]+", frames):
        starts.add(int(match.group(1), 16) & ~1)
    if abi == "armeabi-v7a":
        dump = subprocess.run(
            [readelf, "-x", ".ARM.exidx", str(library)], capture_output=True, text=True
        ).stdout
        for line in dump.splitlines():
            match = re.match(r"^\s*0x([0-9a-f]+)\s+((?:[0-9a-f]{8}\s+){1,4})", line)
            if not match:
                continue
            base = int(match.group(1), 16)
            for index, group in enumerate(match.group(2).split()):
                if index % 2:
                    continue
                word = int.from_bytes(bytes.fromhex(group), "little")
                offset = word & 0x7FFFFFFF
                if word & 0x40000000:
                    offset -= 1 << 31
                starts.add((base + index * 4 + offset) & ~1)
    checked = 0
    for entry in per_abi["bound_dynamic"]:
        if entry.get("confirmed_by") != "runtime_table":
            continue
        assert int(entry["fn_addr"], 16) in starts, entry
        checked += 1
    assert checked == 4, abi


@pytest.mark.skipif(
    not _nyxstone_available(), reason="the runtime-table recovery decodes through nyxstone"
)
@pytest.mark.parametrize("library", ["liba13ctl_x86.so", "liba13ctl_x86_stripped.so"])
def test_sret_trigger_requires_the_callees_own_pop_proof(library: str) -> None:
    """The i386 sret trigger fires only on a callee whose own returns
    prove a callee-pop. A registrar that hands a frame pointer as its
    first argument to a plain-`ret` LOCAL callee (CtlTouch), to an
    external libc call no sibling defines (CtlFormat, snprintf), or to a
    sibling-defined plain-`ret` callee (CtlExtTouch) - each between its
    entry stores and its methods lea - still binds: those calls shift
    nothing. A trigger without the proof loses all three."""
    import lief

    from blint.lib.jni_findclass import recover_runtime_tables

    parsed = lief.ELF.parse(str(FIXTURES / library))
    registrations = {r["class"] for r in recover_runtime_tables(parsed)}
    # the three false-fire rows bind; the genuine control needs its finder
    # verified in the sibling, which the plain walk cannot do
    for row in ("CtlTouch", "CtlFormat", "CtlExtTouch"):
        assert f"com.blint.a13.ctl.{row}" in registrations, (library, row)
    assert "com.blint.a13.ctl.CtlSret" not in registrations, library


@pytest.mark.skipif(
    not _nyxstone_available(), reason="the runtime-table recovery decodes through nyxstone"
)
@pytest.mark.parametrize("library", ["liba13ctl_x86.so", "liba13ctl_x86_stripped.so"])
def test_external_pop_resolver_verifies_in_the_defining_sibling(library: str) -> None:
    """An imported callee is verified in the sibling library that exports
    it (liba13ctlfb stands in for libfbjni). The finder ends ``ret 4`` - a uniform callee pop - so the
    CtlSret registrar's words align only when the resolver hands the walk
    that proof; the sibling's plain-`ret` helper and an unknown symbol
    resolve to no pop and never fire."""
    import lief

    from blint.lib.jni_findclass import external_pop_resolver, recover_runtime_tables

    parsed = lief.ELF.parse(str(FIXTURES / library))
    sibling_bytes = (FIXTURES / "liba13ctlfb_x86.so").read_bytes()
    resolver = external_pop_resolver(
        lambda loc: sibling_bytes if loc.endswith("liba13ctlfb_x86.so") else None,
        ["lib/x86/liba13ctl_x86.so", "lib/x86/liba13ctlfb_x86.so"],
    )
    assert resolver("_Z12a13_ctl_findP7_JNIEnvPKc") == 4
    assert resolver("_Z17a13_ctl_touch_extPKv") == 0
    assert resolver("memcpy") == 0
    without = {
        r["class"]: tuple((e["name"], e["signature"], e["fn_addr"]) for e in r["entries"])
        for r in recover_runtime_tables(parsed)
    }
    with_resolver = {
        r["class"]: tuple((e["name"], e["signature"], e["fn_addr"]) for e in r["entries"])
        for r in recover_runtime_tables(parsed, pop_for_external=resolver)
    }
    assert set(without) < set(with_resolver), (library, without, with_resolver)
    assert "com.blint.a13.ctl.CtlSret" in with_resolver, library
    expected = (("ctlOne", "(I)I", with_resolver["com.blint.a13.ctl.CtlSret"][0][2]),)
    assert with_resolver["com.blint.a13.ctl.CtlSret"] == expected
    for row in ("CtlTouch", "CtlFormat", "CtlExtTouch", "CtlSret"):
        assert (
            with_resolver[f"com.blint.a13.ctl.{row}"] == with_resolver["com.blint.a13.ctl.CtlSret"]
        ), (library, row)


@pytest.mark.skipif(
    not _nyxstone_available(), reason="the runtime-table recovery decodes through nyxstone"
)
def test_callee_pop_needs_every_return_to_agree() -> None:
    """A callee proves a pop only when every return in its window is the
    same ``ret imm``. The finder's ``ret 4`` read together with its
    plain-``ret`` neighbour, as when no start separates the two, proves
    nothing; the finder alone proves 4."""
    import lief
    from nyxstone import Nyxstone

    from blint.lib.jni_findclass import (
        _exec_sections,
        _exported_functions,
        _function_starts,
        _i386_callee_pop,
    )

    parsed = lief.ELF.parse(str(FIXTURES / "liba13ctlfb_x86.so"))
    exported = _exported_functions(parsed)
    finder = exported["_Z12a13_ctl_findP7_JNIEnvPKc"]
    neighbour = exported["_Z17a13_ctl_touch_extPKv"]
    starts = sorted(_function_starts(parsed))
    assert starts[starts.index(finder) + 1] == neighbour
    nyxstone = Nyxstone(target_triple="i386-unknown-linux-android", immediate_style=0)
    sections = _exec_sections(parsed)
    assert _i386_callee_pop(nyxstone, sections, starts, finder, {}) == 4
    assert _i386_callee_pop(nyxstone, sections, starts, neighbour, {}) == 0
    merged = [start for start in starts if start != neighbour]
    assert _i386_callee_pop(nyxstone, sections, merged, finder, {}) == 0


@pytest.mark.skipif(
    not _nyxstone_available(), reason="the runtime-table recovery decodes through nyxstone"
)
@pytest.mark.parametrize("library", ["liba13held_x86.so", "liba13held_thumb_armeabi-v7a.so"])
def test_held_registration_skips_a_consumed_class_name(library: str) -> None:
    """A held registration pairs only with a class name no later vtable
    call consumes. The registrar's first table goes into the jclass Java
    passed in; the one class it names, found below that call, a second
    RegisterNatives consumes - so heldOne is never attributed to it."""
    import lief

    from blint.lib.jni_findclass import recover_runtime_tables

    parsed = lief.ELF.parse(str(FIXTURES / library))
    recovered = {
        (r["class"], e["name"]) for r in recover_runtime_tables(parsed) for e in r["entries"]
    }
    assert ("com.blint.a13.held.HeldNamed", "heldOne") not in recovered, library
    if library == "liba13held_x86.so":
        assert recovered == {("com.blint.a13.held.HeldNamed", "heldTwo")}


# ------------------------------------------------- the jna_direct join


@pytest.mark.parametrize("abi", ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"])
def test_a14_jna_direct_binds_every_registered_shape(abi: str) -> None:
    """Every register shape binds through ``confirmed_by: jna_direct`` in
    every ABI that ships libjnidispatch.so: the constant at the call
    (A14Direct), the constant the invoked helper returns (A14Helper,
    uniffi's findLibraryName shape), the call inside a method the
    ``<clinit>`` runs (A14ViaInit), a self-registration another class's
    ``<clinit>`` triggers (A14SelfRegistrar), the caller-class overload
    from a nested class (A14Outer) and another class's literal
    (A14RegisteredByBootstrap)."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    path = str(FIXTURES / "a14-jna.apk")
    join = build_jni_join_summary(path, scan_android_native(path), confirm_findclass=True)
    per_abi = join["per_abi"][abi]
    jna_rows = {(e["class"].rsplit(".", 1)[-1], e["name"]): e for e in per_abi["bound_dynamic"]}
    for cls, method in (
        ("A14Direct", "a14_direct_add"),
        ("A14Helper", "a14_helper_mul"),
        ("A14ViaInit", "a14_via_init"),
        ("A14SelfRegistrar", "a14_self_registrar"),
        ("A14Outer", "a14_outer_fn"),
        ("A14RegisteredByBootstrap", "a14_bootstrap_real"),
    ):
        row = jna_rows.get((cls, method))
        assert row is not None, (abi, cls, method)
        assert row["confirmed_by"] == "jna_direct", (abi, cls, method)
        assert row["library"] == "liba14jna.so", (abi, cls, method)
    assert per_abi["counts"]["jna_direct"] == 6, abi


def test_a14_jna_constant_picks_between_exporters() -> None:
    """liba14other.so also exports a14_helper_mul; A14Helper's register
    constant names liba14jna.so, and only that library may bind the row -
    the uniqueness the corpus measurement found is per the registered library, not per
    the whole ABI."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    path = str(FIXTURES / "a14-jna.apk")
    join = build_jni_join_summary(path, scan_android_native(path), confirm_findclass=True)
    for abi, per_abi in join["per_abi"].items():
        row = next(e for e in per_abi["bound_dynamic"] if e["name"] == "a14_helper_mul")
        assert row["library"] == "liba14jna.so", abi


def test_a14_jna_two_exporters_stay_ambiguous() -> None:
    """A14Ambiguous registers against the process library (no constant)
    and both libraries export the name: the row stays ambiguous with
    every exporter listed."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    path = str(FIXTURES / "a14-jna.apk")
    join = build_jni_join_summary(path, scan_android_native(path), confirm_findclass=True)
    for abi, per_abi in join["per_abi"].items():
        row = next(e for e in per_abi["ambiguous_dynamic"] if e["name"] == "a14_ambiguous")
        assert row["jna_exporters"] == ["liba14jna.so", "liba14other.so"], abi
        assert "table_candidates" not in row, abi


def test_a14_jna_negative_twin_stays_unbound() -> None:
    """A14Twin declares the same natives against the same exports but
    never calls Native.register - System.loadLibrary is the JNI path and
    binds nothing by plain name."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    path = str(FIXTURES / "a14-jna.apk")
    join = build_jni_join_summary(path, scan_android_native(path), confirm_findclass=True)
    for abi, per_abi in join["per_abi"].items():
        unbound = {e["name"] for e in per_abi["unbound_dex_natives"]}
        assert "a14_twin_echo" in unbound, abi


def test_a14_jna_needs_the_disassemble_flag() -> None:
    """The Native.register evidence is a dex bytecode walk the default
    join does not do; without --disassemble no row binds through it."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    path = str(FIXTURES / "a14-jna.apk")
    native = scan_android_native(path)
    plain = build_jni_join_summary(path, native, confirm_findclass=False)
    for abi, per_abi in plain["per_abi"].items():
        assert per_abi["counts"]["jna_direct"] == 0, abi
        assert not per_abi["bound_dynamic"], abi
        assert per_abi["counts"]["unbound_dex_natives"] == 12, abi


def test_a14_jna_needs_libjnidispatch_in_the_abi() -> None:
    """The nodispatch twin ships the same libraries without the dispatch
    stub: JNA cannot load there, and no row binds in that ABI."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    path = str(FIXTURES / "a14-jna-nodispatch.apk")
    join = build_jni_join_summary(path, scan_android_native(path), confirm_findclass=True)
    for abi, per_abi in join["per_abi"].items():
        assert per_abi["counts"]["jna_direct"] == 0, abi
        assert per_abi["counts"]["unbound_dex_natives"] == 12, abi


def test_a14_jna_register_evidence_shapes() -> None:
    """The dex walk reads the registered class and the library constant
    from each shape: the call itself, the helper's fallback, the
    process-library registration without a constant, and a name that is
    not one constant on every path (a computed field read, a branch)."""
    from blint.lib.binary import parse_dex
    from blint.lib.jni import collect_jna_register_facts

    evidence = collect_jna_register_facts(parse_dex(str(FIXTURES / "a14-jna-classes.dex")))
    assert evidence["com.blint.a14.jna.A14Direct"] == {"library": "a14jna"}
    assert evidence["com.blint.a14.jna.A14Helper"] == {"library": "a14jna"}
    assert evidence["com.blint.a14.jna.A14ViaInit"] == {"library": "a14jna"}
    assert evidence["com.blint.a14.jna.A14Ambiguous"] == {"library": None}
    assert evidence["com.blint.a14.jna.A14SelfRegistrar"] == {"library": "a14jna"}
    assert evidence["com.blint.a14.jna.A14Outer"] == {"library": "a14jna"}
    assert evidence["com.blint.a14.jna.A14RegisteredByBootstrap"] == {"library": "a14jna"}
    assert evidence["com.blint.a14.jna.A14Stale"] == {"library": None}
    assert evidence["com.blint.a14.jna.A14Branch"] == {"library": None}
    # the negative twin never registers; the others register another class
    for cls in ("A14Twin", "A14Caller", "A14Outer$Init", "A14Bootstrap"):
        assert f"com.blint.a14.jna.{cls}" not in evidence, cls


@pytest.mark.skipif(_llvm_readelf() is None, reason="the fn_addr oracle reads llvm-readelf")
@pytest.mark.parametrize("abi", ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"])
def test_a14_jna_fn_addrs_pass_the_symbol_oracle(abi: str) -> None:
    """Every jna_direct fn_addr equals the dynsym value llvm-readelf
    reports for that name in that ABI's own copy - never another ABI's."""
    import subprocess

    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    path = str(FIXTURES / "a14-jna.apk")
    join = build_jni_join_summary(path, scan_android_native(path), confirm_findclass=True)
    rows = [
        e for e in join["per_abi"][abi]["bound_dynamic"] if e.get("confirmed_by") == "jna_direct"
    ]
    assert rows, abi
    readelf = _llvm_readelf()
    symbols: dict[tuple[str, str], str] = {}
    for library, member in (
        (f"liba14jna_{abi}.so", "liba14jna.so"),
        (f"liba14other_{abi}.so", "liba14other.so"),
    ):
        out = subprocess.run(
            [readelf, "--dyn-syms", str(FIXTURES / library)],
            capture_output=True,
            text=True,
        ).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 8 and parts[3] == "FUNC" and parts[6] != "UND":
                symbols[(member, parts[7].split("@")[0])] = f"0x{int(parts[1], 16):x}"
    for row in rows:
        assert symbols[(row["library"], row["name"])] == row["fn_addr"], (
            abi,
            row["library"],
            row["name"],
            row["fn_addr"],
        )


def test_a14_jna_registration_binds_the_registered_class_only() -> None:
    """JNA binds the natives of the class the register call names, not of
    the class that makes the call: A14Bootstrap registers
    A14RegisteredByBootstrap by its literal, and A14Caller's <clinit> runs
    A14SelfRegistrar's registrar. The registered classes bind; the callers'
    own decoys (whose names the library exports) stay unbound."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    path = str(FIXTURES / "a14-jna.apk")
    join = build_jni_join_summary(path, scan_android_native(path), confirm_findclass=True)
    for abi, per_abi in join["per_abi"].items():
        unbound = {e["name"] for e in per_abi["unbound_dex_natives"]}
        bound = {e["name"]: e for e in per_abi["bound_dynamic"]}
        assert {"a14_bootstrap_decoy", "a14_caller_decoy"} <= unbound, abi
        for name in ("a14_bootstrap_real", "a14_self_registrar"):
            assert bound[name]["confirmed_by"] == "jna_direct", (abi, name)
            assert bound[name]["library"] == "liba14jna.so", (abi, name)


def test_a14_jna_library_constant_holds_on_every_path() -> None:
    """A constant names the library only when it holds on every path to the
    register call. A14Stale passes a field read in a register that held
    "a14jna" earlier, and A14Branch passes "a14other" or "a14jna" by
    branch; both libraries export each name, so both rows stay ambiguous
    with every exporter listed - never bound to the stale or last-seen
    constant's library."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    path = str(FIXTURES / "a14-jna.apk")
    join = build_jni_join_summary(path, scan_android_native(path), confirm_findclass=True)
    for abi, per_abi in join["per_abi"].items():
        ambiguous = {e["name"]: e for e in per_abi["ambiguous_dynamic"]}
        for name in ("a14_stale", "a14_branch"):
            assert ambiguous[name]["jna_exporters"] == ["liba14jna.so", "liba14other.so"], (
                abi,
                name,
            )


@pytest.mark.skipif(
    not _nyxstone_available(), reason="the JNI edges need the disassembled native graph"
)
def test_jni_edges_and_counts_read_the_full_join(monkeypatch) -> None:
    """The listing cap cuts the metadata copy only: the callgraph's JNI edges
    come from the full join, so a declaration past the cap still gains its
    edge, and the capped copy keeps the full counts beside its flags."""
    import tempfile

    from blint.lib import jni
    from blint.lib.android import analyze_android_app
    from blint.lib.android_native import LibraryReader, scan_android_native
    from blint.lib.binary import parse
    from blint.lib.runners import _materialize_apk_member

    monkeypatch.setattr(jni, "JOIN_LISTING_CAP", 1)
    apk = str(FIXTURES / "a5-jni-arm64-v8a.apk")
    native = scan_android_native(apk)
    join = jni.build_jni_join_summary(apk, native, capped=False)
    counts = join["per_abi"]["arm64-v8a"]["counts"]
    rows = counts["bound"] + counts["bound_dynamic"]
    assert rows > 1
    capped = jni.cap_jni_join(join)
    capped_abi = capped["per_abi"]["arm64-v8a"]
    assert capped_abi["counts"] == counts
    assert len(capped_abi["bound"]) + len(capped_abi["bound_dynamic"]) < rows
    assert capped_abi.get("bound_truncated") or capped_abi.get("bound_dynamic_truncated")
    assert len(join["per_abi"]["arm64-v8a"]["bound"]) == counts["bound"]
    units = []
    with tempfile.TemporaryDirectory(prefix="jni_full_") as tmp, LibraryReader(apk) as reader:
        for lib in native["libraries"]:
            loc = next((x for x in lib["locations"] if x["abi"] == "arm64-v8a"), None)
            if loc:
                member = parse(_materialize_apk_member(tmp, reader, loc), disassemble=True)
                units.append(
                    {
                        "abi": "arm64-v8a",
                        "library": lib["name"],
                        "callgraph": member.get("callgraph"),
                    }
                )
    app = analyze_android_app(apk, build_cg=True)
    graph = jni.extend_app_callgraph_with_jni(app["callgraph"], join, units)
    assert graph["jni_edge_count"] == rows
