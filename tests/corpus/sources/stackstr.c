#include <stdio.h>
#include <string.h>

__attribute__((noinline)) void leak(const char *s) { printf("%s\n", s); }

__attribute__((noinline)) void build_secret() {
    // Deliberately mid-level: forces the compiler to keep the word-by-word
    // stack construction visible in the disassembly.
    volatile char buf[32];
    memset((void *)buf, 0, sizeof(buf));
    volatile char *p = buf;
    p[0] = '/'; p[1] = 'u'; p[2] = 's'; p[3] = 'r';
    p[4] = '/'; p[5] = 'l'; p[6] = 'i'; p[7] = 'b';
    leak((const char *)buf);
}

int main() { build_secret(); return 0; }
