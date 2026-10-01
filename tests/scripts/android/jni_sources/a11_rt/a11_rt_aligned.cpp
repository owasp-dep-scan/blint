/*
 * A11 S1 - the alignment registrar, compiled with -mstackrealign so the
 * 32-bit prologue realigns esp (`and esp, -16`) before the entry stores:
 * the rebase the i386 model must survive for the stores and the methods
 * lea to still name the same buffer. 64-bit builds of this TU exercise
 * the same source without a realignment (their ABI keeps rsp aligned).
 */
#include <jni.h>

__attribute__((visibility("default"))) jint a11_rt_one(JNIEnv *env, jobject thiz, jint x);

static const char a11_rt_aligned_name[] = "rtOne";
extern const char a11_rt_one_sig[];  /* defined in a11_rt_tables.cpp */

struct a11_rt_pair {
    const JNINativeMethod *methods;
    jint count;
};

/* the pair-passing registrar's helper: exported, so the tables TU's call
 * crosses the PLT and the 8-byte by-value pair stages on the stack */
__attribute__((noinline)) __attribute__((visibility("default"))) void a11_rt_register_pair(JNIEnv *env, a11_rt_pair pair)
{
    jclass cls = env->FindClass("com/blint/a11/rt/RtPair");
    if (cls == NULL) {
        return;
    }
    env->RegisterNatives(cls, pair.methods, pair.count);
}

__attribute__((noinline)) __attribute__((visibility("default"))) void a11_rt_register_pair_again(JNIEnv *env, a11_rt_pair pair)
{
    jclass cls = env->FindClass("com/blint/a11/rt/RtPair");
    if (cls == NULL) {
        return;
    }
    env->RegisterNatives(cls, pair.methods, pair.count);
}

__attribute__((noinline)) __attribute__((visibility("default"))) void a11_rt_register_aligned(JNIEnv *env)
{
    JNINativeMethod methods[1];
    methods[0].name = a11_rt_aligned_name;
    methods[0].signature = a11_rt_one_sig;
    methods[0].fnPtr = (void *) a11_rt_one;
    jclass cls = env->FindClass("com/blint/a11/rt/RtAligned");
    if (cls == NULL) {
        return;
    }
    env->RegisterNatives(cls, methods, 1);
}
