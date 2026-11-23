/*
 * Source for the ELF memory-safety fixtures in this directory.
 *
 * Every binary here is built from this one file so the variants differ only
 * in the hardening or sanitizer flag named in build.sh. Three shapes matter:
 *
 * - large_frame gives a frame of several pages, which is what
 *   -fstack-clash-protection turns into stack probes in the prologue;
 * - copy_fixed copies into a fixed-size buffer, which every FORTIFY level
 *   can check, so it emits __*_chk imports whenever fortify is on;
 * - copy_dynamic copies a caller-chosen size into a heap buffer, which only
 *   -D_FORTIFY_SOURCE=3 can check (the object size is computed at run time),
 *   so it is the one call site that separates level 3 from level 2.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BIG (64 * 1024)

int large_frame(const char *in) {
    char buf[BIG];
    snprintf(buf, sizeof(buf), "%s", in);
    return (int)strlen(buf);
}

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

/* An indirect call through a function pointer: -fsanitize=cfi emits its
 * __cfi_check jump table only for code that has one, so without this the
 * CFI and CFI-less builds would be indistinguishable. */
static int bump(int x) {
    return x + 1;
}

static int (*const table)(int) = bump;

int indirect_call(int x) {
    return table(x);
}

int main(int argc, char **argv) {
    const char *s = argc > 1 ? argv[1] : "probe";
    printf("%d %d %d %d\n", large_frame(s), copy_fixed(s), copy_dynamic(s, strlen(s)),
           indirect_call(argc));
    return 0;
}
