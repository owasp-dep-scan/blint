/*
 * The pair-passing callee. In its own translation unit so the call
 * crosses the PLT like fbjni's registerHybrid, and it makes its own sret
 * call (the class finder) before reading the incoming pair - the shape that
 * shifts an un-compensated i386 frame baseline below the pair.
 */
#include <jni.h>

struct a13_rt_class_ref {
    jclass cls;
    ~a13_rt_class_ref() {}
};

struct a13_rt_pair {
    const JNINativeMethod *methods;
    jint count;
};

/* exported (not static): callers in the other translation unit reach it
 * through the PLT, so the sret result pointer passes as a stack argument
 * the callee pops */
__attribute__((visibility("default"))) a13_rt_class_ref a13_rt_find_class(
    JNIEnv *env, const char *name)
{
    a13_rt_class_ref ref;
    ref.cls = env->FindClass(name);
    return ref;
}

__attribute__((visibility("default"))) void a13_rt_register_pair(JNIEnv *env, a13_rt_pair pair)
{
    a13_rt_class_ref ref = a13_rt_find_class(env, "com/blint/a13/rt/RtPairSret");
    if (ref.cls == NULL) {
        return;
    }
    env->RegisterNatives(ref.cls, pair.methods, pair.count);
}
