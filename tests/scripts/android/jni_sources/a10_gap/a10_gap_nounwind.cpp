/*
 * Compiled with -fno-unwind-tables
 * -fno-asynchronous-unwind-tables (see build_a10_jni_fixtures.sh): the
 * wrapper is a real function - llvm-objdump shows its body - but it carries
 * no .ARM.exidx/.eh_frame entry, and being hidden it has no dynamic symbol
 * either. No function-start source the join reads can name it, which is the
 * RnHello v7a yoga wrappers' situation: the triple's words relocate onto it
 * correctly and the recovery must still refuse the entry.
 */
#include <jni.h>

extern "C" __attribute__((visibility("hidden"))) jint
a10_nounwind_add(JNIEnv *env, jobject thiz, jint x)
{
    (void) env;
    (void) thiz;
    return x + 41;
}
