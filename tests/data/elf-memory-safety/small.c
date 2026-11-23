/*
 * Variant of probe.c without large_frame: no function here grows the stack
 * by a page, so -fstack-clash-protection has nothing to probe and a scanner
 * cannot tell the flag's presence from its absence. Built once per arch as
 * gcc-small-only for exactly that "not determined" case.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int copy_fixed(const char *in) {
    char out[32];
    snprintf(out, sizeof(out), "%s", in);
    return (int)strnlen(out, sizeof(out));
}

int copy_dynamic(const char *in, size_t n) {
    char *out = malloc(n + 1);
    if (!out) {
        return -1;
    }
    memcpy(out, in, n);
    out[n] = 0;
    int r = (int)strlen(out);
    free(out);
    return r;
}

int main(int argc, char **argv) {
    const char *s = argc > 1 ? argv[1] : "probe";
    printf("%d %d\n", copy_fixed(s), copy_dynamic(s, strlen(s)));
    return 0;
}
