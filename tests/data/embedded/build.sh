#!/bin/sh
# Rebuilds the embedded-library fixtures (aarch64 ELF, glibc) in a Debian
# container: docker run --rm -v "$PWD:/src" -w /src debian:bookworm-slim sh build.sh
set -e
command -v gcc >/dev/null || { apt-get update -qq && apt-get install -y -qq gcc libc6-dev >/dev/null; }
CFLAGS="-O2 -shared -fPIC -s -Wl,-z,max-page-size=4096 -Wl,--build-id=none"
gcc $CFLAGS -o brotli-1.2.0-unpatched.so brotli_error_table.c
gcc $CFLAGS -DBLOCK_SWITCH -o brotli-1.2.1-patched.so brotli_error_table.c
gcc $CFLAGS -DBARE_NAMES -DBLOCK_SWITCH -o brotli-1.0.9-backport.so brotli_error_table.c
gcc $CFLAGS -DNODE_VERSION_STRING='"24.22.0"' -o node-24.22.0.so node_runtime.c brotli_error_table.c
gcc $CFLAGS -DNODE_VERSION_STRING='"24.22.1"' -DBLOCK_SWITCH -o node-24.22.1.so node_runtime.c brotli_error_table.c
gcc $CFLAGS -DBARE_NAMES -o libSystem.IO.Compression.Native.so dotnet_compression_native.c brotli_error_table.c
gcc $CFLAGS -DPRODUCT_VERSION='"8.0.32"' -o libSystem.IO.Compression.Native-product.so dotnet_compression_native.c brotli_error_table.c
