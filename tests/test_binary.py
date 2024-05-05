import os

from blint.binary import demangle_symbolic_name, parse


def test_parse():
    if os.path.exists("/bin/ls"):
        metadata = parse("/bin/ls")
        assert metadata


def test_demangle():
    assert demangle_symbolic_name("_ZN4core3ptr79drop_in_place$LT$alloc..vec..Vec$LT$wast..component..types..VariantCase$GT$$GT$17h41b828a7ca01b8c4E.llvm.12153207245666130899") == "core::ptr::drop_in_place<alloc::vec::Vec<wast::component::types::VariantCase>>"
    assert demangle_symbolic_name("_ZN5tokio7runtime4task7harness20Harness$LT$T$C$S$GT$8complete17h79b950493dfd179dE.llvm.3144946739014404372") == "tokio::runtime::task::harness::Harness<T,S>::complete"
    assert demangle_symbolic_name("_ZN4core3ptr252drop_in_place$LT$core..result..Result$LT$$LP$alloc..collections..vec_deque..VecDeque$LT$core..result..Result$LT$tokio..fs..read_dir..DirEntry$C$std..io..error..Error$GT$$GT$$C$std..fs..ReadDir$C$bool$RP$$C$tokio..runtime..task..error..JoinError$GT$$GT$17hb2a9b81fd7c41483E.llvm.17332334537075604262") == "core::ptr::drop_in_place<core::result::Result<(alloc::collections::vec_deque::VecDeque<core::result::Result<tokio::fs::read_dir::DirEntry,std::io::error::Error>>,std::fs::ReadDir,bool),tokio::runtime::task::error::JoinError>>"
    assert demangle_symbolic_name("_ZN6anyhow5error31_$LT$impl$u20$anyhow..Error$GT$9construct17h41b87edbd45e0d86E.llvm.16823983138386609681") == "anyhow::error::<impl anyhow::Error>::construct"
