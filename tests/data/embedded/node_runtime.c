/*
 * Mirrors the version-bearing strings a Node.js release binary carries:
 * process.release.sourceUrl / headersUrl (src/node_metadata.cc,
 * NODE_RELEASE_URLFPFX) and the inspector's /json/version "Browser" field
 * (src/inspector_socket_server.cc), plus one Node-API export, which only the
 * runtime defines. Build with -DNODE_VERSION_STRING='"24.22.1"'.
 */
#define RELEASE "https://nodejs.org/download/release/v" NODE_VERSION_STRING "/node-v" NODE_VERSION_STRING

__attribute__((used)) const char *const node_release_strings[] = {
    RELEASE ".tar.gz",
    RELEASE "-headers.tar.gz",
    "node.js/v" NODE_VERSION_STRING,
};

int napi_create_object(void *env, void **result) {
  (void)env;
  *result = (void *)node_release_strings[0];
  return 0;
}
