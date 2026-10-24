/*
 * Node.js's zlib.constants names for the brotli decoder errors
 * (src/node_zlib.cc NODE_DEFINE_CONSTANT), compiled from the same brotli
 * headers as the decoder it bundles: -DBLOCK_SWITCH for the fixed ones.
 * lld -O2 merges string tails, so the decoder's own
 * "_ERROR_FORMAT_EXUBERANT_NIBBLE" ends up as the tail of
 * "BROTLI_DECODER_ERROR_FORMAT_EXUBERANT_NIBBLE".
 */
#define C(n) "BROTLI_DECODER_ERROR_FORMAT_" #n
__attribute__((used)) const char *const node_zlib_constants[] = {
  C(EXUBERANT_NIBBLE), C(RESERVED), C(EXUBERANT_META_NIBBLE), C(SIMPLE_HUFFMAN_ALPHABET),
  C(SIMPLE_HUFFMAN_SAME), C(CL_SPACE), C(HUFFMAN_SPACE), C(CONTEXT_MAP_REPEAT), C(DISTANCE),
#ifdef BLOCK_SWITCH
  C(BLOCK_SWITCH),
#endif
};
