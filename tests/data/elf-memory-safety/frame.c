/* A 20000-byte frame (big) beside a function that zeroes stack locals at
   the stack top (zero_locals): the stores look like probes and must not
   count as stack-clash protection. Built by build.sh. */
#include <stdio.h>
struct P { long a, b, c, d; };
__attribute__((noinline)) void use(struct P *p) { printf("%ld\n", p->a + p->b + p->c + p->d); }
__attribute__((noinline)) void zero_locals(long v) { struct P s = {0, v, 0, 0}; use(&s); }
__attribute__((noinline)) long big(int n) {
    volatile char buf[20000];
    for (int i = 0; i < n; i++) buf[i * 7 % 20000] = (char)i;
    return buf[n % 20000];
}
int main(int argc, char **argv) { zero_locals(argc); return (int)big(argc); }
