# native_probe.py oracle fixtures

Real tool output over the tier-1 corpus fixture
`tier1-ndk/r28/armeabi-v7a/libhello.so` (and the x86 twin), recorded
2026-09-24 from NDK r28c (`28.2.13676358`, `llvm-*` LLVM 19.0.1,
`darwin-x86_64` toolchain) with these commands:

```
llvm-readelf --symbols --wide  libhello.so > libhello-v7a-readelf-symbols.txt
llvm-readelf --unwind          libhello.so > libhello-v7a-readelf-unwind.txt
llvm-objdump -d --no-show-raw-insn --triple=armv7-linux-androideabi  libhello.so > libhello-v7a-objdump-arm.txt
llvm-objdump -d --no-show-raw-insn --triple=thumbv7-linux-androideabi libhello.so > libhello-v7a-objdump-thumb.txt
llvm-objdump -d --no-show-raw-insn --triple=i686-linux-android --x86-asm-syntax=intel libhello.so > libhello-x86-objdump-intel.txt
```

The `.so` inputs are the A0.2 tier-1 NDK builds (sources in
`tests/scripts/android/jni_sources/`, built by
`build_android_corpus.py tier1`); they are not committed, only these
recorded outputs are. Tests assert against the recorded text (parsing),
never against counts from another machine's run.
