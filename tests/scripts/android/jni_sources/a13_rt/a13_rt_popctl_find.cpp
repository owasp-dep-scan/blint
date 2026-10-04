/*
 * The sibling library for the popctl fixture
 * (liba13ctlfb_x86.so, the libfbjni stand-in). It defines the external
 * callees the registrar library reaches through its PLT: the sret class
 * finder (one word with a non-trivial destructor returns through a hidden
 * caller-frame pointer and pops it - `ret 4`, the fbjni findClassLocal
 * shape) and a plain-`ret` helper, so the external-pop resolver must
 * verify where these are defined and accept one while refusing the other.
 */
#include <jni.h>

struct a13_ctl_ref {
    jclass cls;
    ~a13_ctl_ref() {}
};

__attribute__((visibility("default"))) a13_ctl_ref a13_ctl_find(JNIEnv *env, const char *name)
{
    a13_ctl_ref ref;
    ref.cls = env->FindClass(name);
    return ref;
}

__attribute__((visibility("default"))) int a13_ctl_touch_ext(const void *p)
{
    return *(const volatile char *) p;
}
