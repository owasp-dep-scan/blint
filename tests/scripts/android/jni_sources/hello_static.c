#include <stdio.h>
#include <string.h>

/* Tier-1 planted fixture: a statically linked PIE executable ("static JNI"
 * variant). Built by the real NDK toolchain; a static executable has no
 * DT_NEEDED and no interpreter, which is the known answer the corpus
 * manifest records for it. */

int main(void)
{
    char buf[64];
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf), "blint tier-1 static");
    puts(buf);
    return 0;
}
