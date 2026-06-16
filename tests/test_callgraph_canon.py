# -*- coding: utf-8 -*-
"""Tests for canonical Rust name normalization used by the callgraph matcher."""

import pytest

from blint.lib.callgraph.canon import (
    CanonicalName,
    NameKind,
    canonicalize,
    demangle,
)


def _canon(name: str) -> str:
    return canonicalize(name).value


# Pairs of (binary spelling, source spelling) taken from the wasm-tools-1.247.0
# x86_64-linux binary callgraph and the rusi source callgraph. Each pair must
# reduce to the same canonical name for Layer 0 anchor matching to work.
SOURCE_BINARY_PAIRS = [
    (
        "<wasmparser::readers::core::types::SubType as core::fmt::Debug>::fmt",
        "wasmparser::readers::core::types::SubType::fmt",
    ),
    (
        "wasmparser::validator::operators::OperatorValidatorTemp<R>::label_types",
        "wasmparser::validator::operators::OperatorValidatorTemp::label_types",
    ),
    (
        "wasmparser::validator::operators::OperatorValidatorTemp<'a, 'b, R>::pop_operand",
        "wasmparser::validator::operators::OperatorValidatorTemp::pop_operand",
    ),
    (
        "<i32 as core::fmt::Debug>::fmt",
        "i32::fmt",
    ),
]


@pytest.mark.parametrize("binary_name, source_name", SOURCE_BINARY_PAIRS)
def test_source_and_binary_spellings_canonicalize_alike(binary_name, source_name):
    assert _canon(binary_name) == _canon(source_name)
    assert _canon(binary_name) == source_name


def test_strips_compiler_hash_and_llvm_suffix():
    name = (
        "core::ptr::drop_in_place<alloc::vec::Vec<u8>>"
        "::h41b828a7ca01b8c4.llvm.12153207245666130899"
    )
    result = canonicalize(name)
    assert result.value == "core::ptr::drop_in_place"
    assert result.kind == NameKind.GLUE


def test_reduces_trait_qualified_self_with_generic_trait():
    name = (
        "<alloc::string::String as core::ops::index::Index<"
        "core::ops::range::RangeFrom<usize>>>::index"
    )
    assert _canon(name) == "alloc::string::String::index"


def test_reduces_impl_for_block():
    assert _canon("<impl core::fmt::Debug for myapp::Widget>::fmt") == "myapp::Widget::fmt"


def test_reduces_impl_inherent_block():
    assert _canon("<impl myapp::Widget>::new") == "myapp::Widget::new"


def test_collapses_generic_instances_to_single_definition():
    a = _canon("alloc::vec::Vec<u8>::push")
    b = _canon("alloc::vec::Vec<myapp::Token>::push")
    assert a == b == "alloc::vec::Vec::push"


def test_is_generic_flag_tracks_original():
    assert canonicalize("alloc::vec::Vec<u8>::push").is_generic is True
    assert canonicalize("wasm_tools::main").is_generic is False


def test_classifies_method_vs_function():
    assert canonicalize("wasm_tools::dump::Dump::run").kind == NameKind.METHOD
    assert canonicalize("wasm_smith::core::arbitrary_valtype").kind == NameKind.FUNCTION


def test_classifies_closures():
    result = canonicalize("wasm_smith::core::closure_2202_77")
    assert result.kind == NameKind.CLOSURE


def test_classifies_crt_glue():
    assert canonicalize("_start").kind == NameKind.GLUE
    assert canonicalize("register_tm_clones").kind == NameKind.GLUE


def test_empty_input_is_falsy_canonical_name():
    result = canonicalize("   ")
    assert result.value == ""
    assert not result
    assert isinstance(result, CanonicalName)


def test_demangle_legacy_rust_symbol():
    mangled = (
        "_ZN5tokio7runtime4task7harness20Harness$LT$T$C$S$GT$8complete"
        "17h79b950493dfd179dE.llvm.3144946739014404372"
    )
    assert demangle(mangled) == "tokio::runtime::task::harness::Harness<T,S>::complete"


def test_canonicalize_demangles_mangled_input_automatically():
    mangled = (
        "_ZN5tokio7runtime4task7harness20Harness$LT$T$C$S$GT$8complete"
        "17h79b950493dfd179dE.llvm.3144946739014404372"
    )
    assert _canon(mangled) == "tokio::runtime::task::harness::Harness::complete"


def test_demangle_passes_through_already_demangled_names():
    name = "wasmparser::validator::operators::OperatorValidator::new_func"
    assert demangle(name) == name
