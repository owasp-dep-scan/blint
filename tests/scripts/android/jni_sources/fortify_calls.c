#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>

/* Tier-1 planted fixture: calls whose bionic FORTIFY (_FORTIFY_SOURCE)
 * variants (__sprintf_chk, __snprintf_chk, __strcpy_chk, __memcpy_chk,
 * __read_chk) the compiler emits when the macro is set and optimization is
 * on, and whose plain libc names it emits when it is not. The buffer sizes
 * cross blint_sink so the optimizer cannot prove them and inline the checks
 * away (the same trick blint_sink.c uses for the canary). */

void blint_sink(void *p, size_t n);

/* exported so the calls cannot be dead-stripped */
int fortify_exercise(int n, const char *text)
{
    char buf[64];
    char small[8];
    int written = 0;

    written += sprintf(buf, "%d-%s", n, text);
    written += snprintf(buf + written, sizeof(buf) - written, "%d", n * 2);
    strncpy(small, text, (size_t)(n % 8) + 1);
    memcpy(buf, text, (size_t)(n % 32) + 4);
    blint_sink(buf, sizeof(buf));
    blint_sink(small, sizeof(small));
    /* read() with a runtime length: __read_chk validates the buffer bound */
    written += (int)read(0, buf, (size_t)n);
    blint_sink(&written, sizeof(written));
    return written;
}
