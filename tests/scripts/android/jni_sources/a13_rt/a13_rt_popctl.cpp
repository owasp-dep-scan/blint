/*
 * The sret trigger's false-fire controls (the callee-pop
 * verification's regression fixtures).
 *
 *   ctl_register_touched    the entry words are stored, then a NAMED
 *                           LOCAL callee with a plain `ret` receives a
 *                           frame pointer as its first argument, then the
 *                           methods lea. A trigger that fires on "frame
 *                           pointer as arg1 at a named callee" alone
 *                           shifts the frame baseline one word up and
 *                           loses the binding; the production trigger
 *                           verifies the callee's own returns pop.
 *   ctl_register_formatted  the same with an external libc call
 *                           (snprintf into a frame buffer): no sibling
 *                           library in the app defines it, so it can
 *                           never resolve to a popper.
 *   ctl_register_ext_touched  the same with a sibling-defined external
 *                           callee whose own bytes say plain `ret` - the
 *                           resolver must refuse it where it is defined.
 *   ctl_register_sret       the genuine control: the class finder is
 *                           defined in the sibling library (libfbjni's
 *                           findClassLocal shape - the registrar's call
 *                           crosses the PLT to another DSO) and ends
 *                           `ret 4`, so the entry stores and the
 *                           post-call lea only align when the externally
 *                           verified pop is applied.
 *
 * The classes are found inside each registrar (the normal paired shape),
 * so the only reader these rows exercise is the word-reader whose frame
 * baseline the trigger moves.
 */
#include <jni.h>
#include <stdio.h>

__attribute__((visibility("default"))) jint a13_ctl_one(JNIEnv *env, jobject thiz, jint x)
{
    (void) env;
    (void) thiz;
    return x + 1;
}

static const char a13_ctl_one_name[] = "ctlOne";
__attribute__((visibility("default"))) const char a13_ctl_one_sig[] = "(I)I";

/* noinline identity: the fnPtr word is a run-time value, never a static one */
__attribute__((noinline)) static void *a13_ctl_fn(void *fn)
{
    return fn;
}

/* a plain-`ret` local callee that takes a frame buffer as its first
 * argument (and reads it, so the call is not eliminable) */
__attribute__((noinline, visibility("default"))) int a13_ctl_touch(const void *p)
{
    return *(const volatile char *) p;
}

/* the sibling library's callees: the sret class finder (one word with a
 * non-trivial destructor, ends `ret 4`) and a plain-`ret` helper */
struct a13_ctl_ref {
    jclass cls;
    ~a13_ctl_ref() {}
};
__attribute__((visibility("default"))) a13_ctl_ref a13_ctl_find(JNIEnv *env, const char *name);
__attribute__((visibility("default"))) int a13_ctl_touch_ext(const void *p);

__attribute__((noinline)) static void ctl_register_touched(JNIEnv *env)
{
    jclass cls = env->FindClass("com/blint/a13/ctl/CtlTouch");
    JNINativeMethod method;
    char scratch[8] = { 0 };
    method.name = a13_ctl_one_name;
    method.signature = a13_ctl_one_sig;
    method.fnPtr = a13_ctl_fn((void *) a13_ctl_one);
    if (cls == NULL) {
        return;
    }
    if (a13_ctl_touch(scratch) < 0) {
        return;
    }
    env->RegisterNatives(cls, &method, 1);
}

__attribute__((noinline)) static void ctl_register_formatted(JNIEnv *env)
{
    jclass cls = env->FindClass("com/blint/a13/ctl/CtlFormat");
    JNINativeMethod method;
    char scratch[64];
    method.name = a13_ctl_one_name;
    method.signature = a13_ctl_one_sig;
    method.fnPtr = a13_ctl_fn((void *) a13_ctl_one);
    if (cls == NULL) {
        return;
    }
    if (snprintf(scratch, sizeof scratch, "%p", (const void *) env) < 0) {
        return;
    }
    env->RegisterNatives(cls, &method, 1);
}

__attribute__((noinline)) static void ctl_register_ext_touched(JNIEnv *env)
{
    jclass cls = env->FindClass("com/blint/a13/ctl/CtlExtTouch");
    JNINativeMethod method;
    char scratch[8] = { 0 };
    method.name = a13_ctl_one_name;
    method.signature = a13_ctl_one_sig;
    method.fnPtr = a13_ctl_fn((void *) a13_ctl_one);
    if (cls == NULL) {
        return;
    }
    if (a13_ctl_touch_ext(scratch) < 0) {
        return;
    }
    env->RegisterNatives(cls, &method, 1);
}

__attribute__((noinline)) static void ctl_register_sret(JNIEnv *env)
{
    JNINativeMethod method;
    method.name = a13_ctl_one_name;
    method.signature = a13_ctl_one_sig;
    method.fnPtr = a13_ctl_fn((void *) a13_ctl_one);
    a13_ctl_ref ref = a13_ctl_find(env, "com/blint/a13/ctl/CtlSret");
    if (ref.cls == NULL) {
        return;
    }
    env->RegisterNatives(ref.cls, &method, 1);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void) reserved;
    JNIEnv *env = NULL;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    ctl_register_touched(env);
    ctl_register_formatted(env);
    ctl_register_ext_touched(env);
    ctl_register_sret(env);
    return JNI_VERSION_1_6;
}
