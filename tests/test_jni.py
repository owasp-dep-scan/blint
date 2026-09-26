"""JNI surface facts (A5.1 E1).

Every binary input is a real NDK r28c build committed under
tests/data/android/ (build commands in a5-jni-fixtures-manifest.json).
The decoder is a pure string function, so its branch tests use symbol
names, not bytes.
"""

from __future__ import annotations

from pathlib import Path

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
    assert len(by_symbol) == 8
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
    assert block["counts"] == {"java_exports": 8, "decoded": 8, "decode_errors": 0}


def test_stripped_twin_gives_the_same_block() -> None:
    # The exports are dynamic symbols, so stripping changes nothing.
    assert _jni_block("liba5_static_arm64-v8a.so") == _jni_block(
        "liba5_static_arm64-v8a_stripped.so"
    )
    assert _jni_block("liba5_dynamic_armeabi-v7a.so") == _jni_block(
        "liba5_dynamic_armeabi-v7a_stripped.so"
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
    assert len(natives) == 13
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
    assert summary["counts"] == {"dex_natives": 13, "load_library_sites": 6, "abis": 1}
    abi = summary["per_abi"]["arm64-v8a"]
    assert abi["counts"] == {
        "libraries": 2,
        "bound": 7,
        "unbound_dex_natives": 6,
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
    assert ("com.example.blint.jni.Dyn", "dynA1") in unbound  # dynamic (until F1)
    assert ("com.example.blint.jni.NativeEscapes", "missingNative") in unbound
    assert [u["symbol"] for u in abi["undeclared_exports"]] == [
        "Java_com_example_blint_jni_NativeEscapes_orphan"
    ]
    # loadLibrary sites map to the real member names and their ABIs.
    sites = {s["library"]: s for s in summary["load_library"]}
    assert sites["jnistat"]["member"] == "libjnistat.so"
    assert sites["jnistat"]["abis"] == ["arm64-v8a"]
    assert sites["jnidyn"]["member"] == "libjnidyn.so"


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
    result = _join_abi_lists(natives, {}, {"libnone.so": {"arm64-v8a"}}, "arm64-v8a")
    assert result["counts"]["unbound_dex_natives"] == JOIN_LISTING_CAP + 5
    assert len(result["unbound_dex_natives"]) == JOIN_LISTING_CAP
    assert result["unbound_dex_natives_truncated"] is True
    # An under-cap join carries no truncation flag.
    small = _join_abi_lists(natives[:3], {}, {"libnone.so": {"arm64-v8a"}}, "arm64-v8a")
    assert "unbound_dex_natives_truncated" not in small
    assert small["counts"]["unbound_dex_natives"] == 3
