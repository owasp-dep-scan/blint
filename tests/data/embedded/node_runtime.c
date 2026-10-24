/*
 * Mirrors the version-bearing strings a Node.js release binary carries:
 * process.release.sourceUrl / headersUrl (src/node_metadata.cc,
 * NODE_RELEASE_URLFPFX) and the inspector's /json/version "Browser" field
 * (src/inspector_socket_server.cc), plus one Node-API export, which only the
 * runtime defines. Build with -DNODE_VERSION_STRING='"24.22.1"', and with
 * -DNO_RELEASE_URLS for a build without NODE_HAS_RELEASE_URLS, which keeps
 * only the inspector string.
 */
#define RELEASE "https://nodejs.org/download/release/v" NODE_VERSION_STRING "/node-v" NODE_VERSION_STRING

__attribute__((used)) const char *const node_release_strings[] = {
#ifndef NO_RELEASE_URLS
    RELEASE ".tar.gz",
    RELEASE "-headers.tar.gz",
#endif
    "node.js/v" NODE_VERSION_STRING,
};

int napi_create_object(void *env, void **result) {
  (void)env;
  *result = (void *)node_release_strings[0];
  return 0;
}
