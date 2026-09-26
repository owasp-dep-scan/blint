"""JNI surface facts (A5.1 E1).

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
    # The A5 fixture's real symbols, one per mangling rule (JNI spec,
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

    # For the dynamic library the F1 register_natives tables also match,
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
    # hello_static is the NDK r28 tier-1 corpus build of hello_static.c on
    # this reviewer Mac (~/sandbox/android-corpus, llvm-nm -D shows 0 JNI
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


# --------------------------------------------------- A5.2 E2: the join


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
    """The E2 R1 gate: bound equals the fixture's source exactly."""
    from blint.lib.android_native import scan_android_native
    from blint.lib.jni import build_jni_join_summary

    apk = str(FIXTURES / "a5-jni-arm64-v8a.apk")
    summary = build_jni_join_summary(apk, scan_android_native(apk))
    assert summary["counts"] == {"dex_natives": 15, "load_library_sites": 6, "abis": 1}
    abi = summary["per_abi"]["arm64-v8a"]
    # After F1, the five Dyn* declarations bind dynamically and only
    # missingNative stays unbound.
    assert abi["counts"] == {
        "libraries": 2,
        "bound": 9,
        "bound_dynamic": 5,
        "ambiguous_dynamic": 0,
        "unbound_dex_natives": 1,
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
        "libx.so": {
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


# ------------------------------------------------ A5.2 F1: table recovery


def test_register_natives_tables_match_the_fixture_source() -> None:
    """F1's R1 gate: the recovered tables equal the fixture's source -
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


# --------------------------------------------- A5.2 F2: the callgraph edge


def test_node_name_is_the_pools_own_rendering() -> None:
    """The join records each native's dex callgraph node name from
    DexPools._render_method - the same function that builds the graph's
    names - never a re-derived string (this LIEF renders Z as `bool`,
    not `boolean`; a synthesized table missed that, caught on the R4
    rung). A boolean-returning native is declared in the fixture to pin
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
    """The F2 R1 demo: a Java method -> its native declaration -> the JNI
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

    # R1 gate: the jni edge count equals bound + bound_dynamic.
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
    # thunk; llvm-objdump in the F2 run names target 0x4c60 getpid@plt -
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
