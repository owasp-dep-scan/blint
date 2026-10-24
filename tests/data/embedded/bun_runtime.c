/*
 * Mirrors what Bun carries that names Node.js: process.release.headersUrl of
 * the Node.js release it is compatible with, beside its own version strings,
 * and Node-API, which Bun implements itself. Bun is not Node.js, so none of
 * this is a Node.js runtime.
 */
__attribute__((used)) const char *const bun_strings[] = {
    "https://nodejs.org/download/release/v26.3.0/node-v26.3.0-headers.tar.gz",
    "Bun v1.4.3 (c6da4a4d3) Linux arm64",
    "bun-v1.4.3",
};

int napi_create_object(void *env, void **result) {
  (void)env;
  *result = (void *)bun_strings[0];
  return 0;
}
