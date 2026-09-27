# G2 measurements — what the G1 extent fix unblocks (2026-09-27)

Host: reviewer Mac, darwin arm64; blint `feat/an-a6` @ G1; lief
1.0.0-d05b3499b; nyxstone 0.1.8 / LLVM 18.1.8
(`/opt/homebrew/opt/llvm@18`, `NYXSTONE_LLVM_PREFIX` set). Commands:
`/usr/bin/time -l poetry run blint -q --no-banner --no-reviews -i <apk>
-o <out> --disassemble`. This file is the commit-body record; nothing
under `blint/` changes in this packet.

## RnHello (`com.blint.rnhello_1.apk`, 4 ABIs × 10 libraries)

- Wall time **356.1 s**, peak RSS **3.68 GB**, output tree **880 MB**.
  (Before G1 this run was not completable at all: the reviewer measured a
  projected ~30 GB and hours for `libreactnative.so` alone, driven by
  1,267 wrapped-size functions decoding to the end of `.text`.)
- Per arm64-v8a library (the ABI the A5 gates use), metadata JSON vs the
  library's own file size:

| library                     | metadata   | file      | ratio |
|-----------------------------|-----------|------------|-------|
| libreactnative.so           | 117.2 MB  | 6.5 MB     | 18.0x |
| libhermes.so                |  47.0 MB  | 2.3 MB     | 20.7x |
| libc++_shared.so            |  21.3 MB  | 1.3 MB     | 16.0x |
| libjsi.so                   |   6.9 MB  | 0.42 MB    | 16.5x |
| libnative-imagetranscoder.so|  10.2 MB  | 0.55 MB    | 18.7x |
| libfbjni.so                 |   3.0 MB  | 0.19 MB    | 16.2x |
| libappmodules.so            |   0.8 MB  | 0.05 MB    | 15.5x |
| libhermestooling.so         |   2.4 MB  | 0.16 MB    | 15.3x |
| libnative-filters.so        |   0.3 MB  | 0.02 MB    | 13.5x |
| libimagepipeline.so         |   0.1 MB  | 0.0085 MB  | 11.8x |

  The other three ABIs land in the same band (armeabi-v7a and x86 are
  smaller, x86_64 within ±5%). **No library's metadata exceeds 50× its
  file size** — the largest ratio in the app is 20.7× (libhermes).
  No output-size cap is proposed on this evidence; a cap stays a schema
  decision for the ranked proposal.

## Tier-2: VLC (`org.videolan.vlc_13070108.apk`, x86_64 ABI units shown;
the other three ABIs were in the same run)

- Wall time **425.6 s**, peak RSS **9.95 GB** (the v7a/x86 `libvlc.so`
  disassembly pass is the heavyweight), output tree **1.0 GB**.
- Per library (x86_64):

| library           | metadata    | file     | ratio |
|-------------------|-------------|----------|-------|
| libvlc.so         | 789.1 MB    | 49.0 MB  | 16.1x |
| libmla.so         | 112.9 MB    | 5.4 MB   | 20.9x |
| libc++_shared.so  |  22.0 MB    | 1.2 MB   | 18.3x |
| libvlcjni.so      |   1.6 MB    | 0.1 MB   | 16.0x |

  Again nothing over 50×.

## A5 F2 edge count, the real way

The A5 gate measured RnHello's dex→native edges by looking up both ends
directly. Through the full `--disassemble` run the app-level callgraph
carries, on every ABI:

- `jni_dynamic` edges: **111** — equal to the 111 `bound_dynamic` entries
  of that ABI's join, so every dynamic binding found its native node and
  drew its edge. No `jni_static` edges (RnHello has no decoded `Java_*`
  exports; all its natives register dynamically — consistent with A5's
  join).
- `ambiguous_dynamic`: 0, `unbound_dex_natives`: 221 (the known
  fbjni-merged-table limit recorded in #234), `undeclared_exports`: 0.
- The app callgraph totals 275,836 edges (140,242 direct, 131,626
  native-namespace internal, 3,946 tailcall, 22 indirect_hint) — the
  first full-app graph RnHello has ever produced.
