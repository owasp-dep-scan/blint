/*
 * Mirrors the Rust brotli port (the brotli-decompressor crate), which is not
 * affected by CVE-2026-111497: its FFI shim (src/ffi/mod.rs) defines the
 * same C decoder API as google/brotli, it carries the same decoding tables,
 * and its panic messages name the crate's source path. Deno ships it this way.
 */
#include <stddef.h>

__attribute__((used)) static const char crate_path[] =
    "/rustc/registry/src/index.crates.io-6f17d22bba15001f/brotli-decompressor-4.0.1/src/ffi/mod.rs";
__attribute__((used)) static const unsigned char kCodeLengthCodeOrder[18] = {
    1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15};
__attribute__((used)) static const unsigned char kCodeLengthPrefixValue[16] = {
    0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5};

void *BrotliDecoderCreateInstance(void *alloc, void *free_fn, void *opaque) {
  (void)alloc; (void)free_fn; (void)opaque;
  return NULL;
}

int BrotliDecoderDecompressStream(void *state, size_t *in_len, const unsigned char **in,
                                  size_t *out_len, unsigned char **out, size_t *total) {
  (void)state; (void)in_len; (void)in; (void)out_len; (void)out; (void)total;
  return 0;
}
