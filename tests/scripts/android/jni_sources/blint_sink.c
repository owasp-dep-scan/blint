#include <stddef.h>

/* Opaque sink in its own translation unit: hello.c passes the canary-planted
 * buffer's address across this call, which the optimizer cannot see through
 * (no LTO), so the buffer genuinely lives on the stack and the stack
 * protector import stays in the built library. A same-file no-op would be
 * inlined away and the __stack_chk_fail import with it. */
void blint_sink(void *p, size_t n)
{
    volatile unsigned char c = ((const unsigned char *)p)[n - 1];
    (void)c;
}
