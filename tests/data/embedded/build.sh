#!/bin/sh
# Rebuilds the embedded-library fixtures (aarch64 ELF, glibc) in a Debian
# container: docker run --rm -v "$PWD:/src" -w /src debian:bookworm-slim sh build.sh
set -e
# The lld fixtures need clang and ld.lld (Homebrew llvm and lld, or any LLVM
# toolchain) and no libc, so they build on the host: sh build.sh lld
if [ "${1:-}" = "lld" ]; then
  LLD="--target=aarch64-linux-gnu -O2 -fno-jump-tables -fPIC -shared -nostdlib -fuse-ld=lld"
  LLD="$LLD -Wl,--build-id=none -s"
  # lld -O2 merges string tails: the decoder's names survive only inside the
  # Node.js constants.
  clang $LLD -Wl,-O2 -o brotli-lld-tailmerged-unpatched.so brotli_error_table.c node_constants.c
  clang $LLD -Wl,-O2 -DBLOCK_SWITCH -o brotli-lld-tailmerged-patched.so \
    brotli_error_table.c node_constants.c
  # The same with the decoder API hidden: only the tables mark the decoder.
  clang $LLD -Wl,-O2 -fvisibility=hidden -DDECODER_TABLES -o brotli-lld-tailmerged-hidden.so \
    brotli_error_table.c node_constants.c
  # The Rust port's FFI shim: the C API and tables, but not the C decoder.
  clang $LLD -o brotli-rust-ffi.so brotli_rust_ffi.c
  # Bun: Node-API and Node.js's headers URL, but not Node.js.
  clang $LLD -o bun-1.4.3.so bun_runtime.c
  exit 0
fi
command -v gcc >/dev/null || { apt-get update -qq && apt-get install -y -qq gcc libc6-dev >/dev/null; }
CFLAGS="-O2 -shared -fPIC -s -Wl,-z,max-page-size=4096 -Wl,--build-id=none"
gcc $CFLAGS -o brotli-1.2.0-unpatched.so brotli_error_table.c
gcc $CFLAGS -DBLOCK_SWITCH -o brotli-1.2.1-patched.so brotli_error_table.c
gcc $CFLAGS -DBARE_NAMES -DBLOCK_SWITCH -o brotli-1.0.9-backport.so brotli_error_table.c
gcc $CFLAGS -DNODE_VERSION_STRING='"24.22.0"' -o node-24.22.0.so node_runtime.c brotli_error_table.c
gcc $CFLAGS -DNODE_VERSION_STRING='"24.22.1"' -DBLOCK_SWITCH -o node-24.22.1.so node_runtime.c brotli_error_table.c
gcc $CFLAGS -DBARE_NAMES -o libSystem.IO.Compression.Native.so dotnet_compression_native.c brotli_error_table.c
gcc $CFLAGS -DPRODUCT_VERSION='"8.0.32"' -o libSystem.IO.Compression.Native-product.so dotnet_compression_native.c brotli_error_table.c
# The Mach-O fixture is built on macOS (arm64): a Homebrew-shaped dylib whose
# own LC_ID_DYLIB names the opt link and current_version 1.2.0.
#   clang -O2 -dynamiclib -install_name /opt/homebrew/opt/brotli/lib/libbrotlidec.1.dylib \
#     -current_version 1.2.0 -compatibility_version 1.0.0 -Wl,-x \
#     -o libbrotlidec.1.2.0.dylib brotli_error_table.c
# The universal Mach-O fixture is built on macOS: an x86_64 slice with the fix
# and an arm64 slice without it.
#   clang -O2 -arch x86_64 -DBLOCK_SWITCH -dynamiclib -Wl,-x -o x86_64.dylib brotli_error_table.c
#   clang -O2 -arch arm64 -dynamiclib -Wl,-x -o arm64.dylib brotli_error_table.c
#   lipo -create x86_64.dylib arm64.dylib -output brotli-universal-x86_64-patched.dylib
# The Mach-O Node.js fixture keeps only the inspector string (no release URLs):
#   clang -O2 -dynamiclib -DNODE_VERSION_STRING='"24.18.0"' -DNO_RELEASE_URLS -Wl,-x \
#     -o node-24.18.0-inspector-only.dylib node_runtime.c
