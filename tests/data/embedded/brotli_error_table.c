/*
 * Mirrors BrotliDecoderErrorString (google/brotli c/dec/decode.c): the
 * decoder compiles its error names into the binary as C strings. Brotli
 * 1.0.x returns the bare name, 1.1.0 onwards prefixes it with
 * "_ERROR_FORMAT_". The CVE-2026-111497 fix (google/brotli 0ed4268) added
 * BLOCK_SWITCH (-17). Build flags select the shape:
 *   -DBARE_NAMES     1.0.x table
 *   -DBLOCK_SWITCH   the fixed table
 *   -DDECODER_TABLES kCodeLengthCodeOrder and kCodeLengthPrefixValue, which stay
 *                    when a linker drops the error-name table
 * Only the decoder's own strings and API names are reproduced here, not its code.
 */
#include <stddef.h>

#ifdef BARE_NAMES
#define ERROR_NAME(name) #name
#else
#define ERROR_NAME(name) "_ERROR_FORMAT_" #name
#endif

const char *BrotliDecoderErrorString(int code) {
  switch (code) {
    case -1: return ERROR_NAME(EXUBERANT_NIBBLE);
    case -2: return ERROR_NAME(RESERVED);
    case -3: return ERROR_NAME(EXUBERANT_META_NIBBLE);
    case -4: return ERROR_NAME(SIMPLE_HUFFMAN_ALPHABET);
    case -5: return ERROR_NAME(SIMPLE_HUFFMAN_SAME);
    case -6: return ERROR_NAME(CL_SPACE);
    case -7: return ERROR_NAME(HUFFMAN_SPACE);
    case -8: return ERROR_NAME(CONTEXT_MAP_REPEAT);
    case -16: return ERROR_NAME(DISTANCE);
#ifdef BLOCK_SWITCH
    case -17: return ERROR_NAME(BLOCK_SWITCH);
#endif
    default: return "INVALID";
  }
}

#ifdef DECODER_TABLES
__attribute__((used)) static const unsigned char kCodeLengthCodeOrder[18] = {
    1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15};
__attribute__((used)) static const unsigned char kCodeLengthPrefixValue[16] = {
    0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5};
#endif

void *BrotliDecoderCreateInstance(void *alloc, void *free_fn, void *opaque) {
  (void)alloc; (void)free_fn; (void)opaque;
  return NULL;
}

int BrotliDecoderDecompressStream(void *state, size_t *in_len, const unsigned char **in,
                                  size_t *out_len, unsigned char **out, size_t *total) {
  (void)state; (void)in_len; (void)in; (void)out_len; (void)out; (void)total;
  return 0;
}
