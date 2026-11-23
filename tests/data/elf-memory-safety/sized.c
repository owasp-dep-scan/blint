/* A copy into a buffer of known size with a run-time length: at
   _FORTIFY_SOURCE=2 this already calls __memcpy_chk and __memset_chk, so
   those wrappers do not mark level 3. Built by build.sh. */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
struct S { char a[64]; long x; };
int main(int argc, char **argv) {
    struct S s;
    size_t n = strlen(argv[0]);
    memcpy(s.a, argv[0], n);            /* known object size, variable length */
    memset(s.a, 0, n / 2);
    puts(s.a);
    return 0;
}
