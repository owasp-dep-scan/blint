/*
 * The 32-bit singles' registrar shapes (see the java declarations'
 * expected fates). The entry words are built per field like the a11
 * fixture's, so no constant aggregate exists for the compiler to place in
 * .data.rel.ro.
 *
 *   a13_rt_register_lazy       the class is found only on the cold init
 *                              path, which the compiler places below the
 *                              hot path holding the RegisterNatives call -
 *                              the RN ThreadScope / CxxCallbackImpl /
 *                              install-binding shape.
 *   a13_rt_register_sret       the entry words are stored before a call
 *                              that returns its result through a
 *                              caller-frame pointer and pops it (the i386
 *                              sret form; fbjni's findClassLocal), so the
 *                              caller re-aligns with `sub esp, 4` between
 *                              the stores and the methods lea.
 *   a13_rt_register_via_pair   the pair-passing chain whose callee makes
 *                              its own sret call before reading the
 *                              incoming pair - the registerHybrid shape.
 *   a13_rt_register_two        the refusal twin: the cold init path names
 *                              two classes, so the call that no class
 *                              precedes stays unread.
 */
#include <jni.h>

/* fn implementations, exported so each ABI's own copy has verified starts */
__attribute__((visibility("default"))) jint a13_rt_one(JNIEnv *env, jobject thiz, jint x)
{
    (void) env;
    (void) thiz;
    return x + 1;
}

__attribute__((visibility("default"))) jlong a13_rt_shared(JNIEnv *env, jobject thiz, jlong t)
{
    (void) env;
    (void) thiz;
    return t + 1;
}

static const char a13_rt_one_name[] = "rtOne";
static const char a13_rt_shared_name[] = "rtShared";
extern const char a13_rt_one_sig[];
extern const char a13_rt_shared_sig[];
__attribute__((visibility("default"))) const char a13_rt_one_sig[] = "(I)I";
__attribute__((visibility("default"))) const char a13_rt_shared_sig[] = "(J)J";

/* noinline identity: the fnPtr word is a run-time value, never a static one */
__attribute__((noinline)) static void *a13_rt_fn(void *fn)
{
    return fn;
}

/* the sret form: a one-word class reference with a non-trivial destructor
 * returns through a hidden caller-frame pointer the callee pops. The finder
 * lives in the other translation unit with external linkage, so callers
 * reach it through the PLT under the plain C ABI - the fbjni shape. */
struct a13_rt_class_ref {
    jclass cls;
    ~a13_rt_class_ref() {}
};

a13_rt_class_ref a13_rt_find_class(JNIEnv *env, const char *name);

/* the lazy-class shape: the cached jclass makes FindClass the cold path */
__attribute__((noinline)) static void a13_rt_register_lazy(JNIEnv *env)
{
    static jclass lazy_cls = NULL;
    JNINativeMethod method;
    method.name = a13_rt_one_name;
    method.signature = a13_rt_one_sig;
    method.fnPtr = a13_rt_fn((void *) a13_rt_one);
    if (__builtin_expect(lazy_cls == NULL, 0)) {
        lazy_cls = env->FindClass("com/blint/a13/rt/RtLazy");
        if (lazy_cls == NULL) {
            return;
        }
    }
    env->RegisterNatives(lazy_cls, &method, 1);
}

/* the sret shape: the words are stored before the finder call, and the
 * methods lea follows the caller's re-alignment */
__attribute__((noinline)) static void a13_rt_register_sret(JNIEnv *env)
{
    JNINativeMethod method;
    method.name = a13_rt_one_name;
    method.signature = a13_rt_one_sig;
    method.fnPtr = a13_rt_fn((void *) a13_rt_one);
    a13_rt_class_ref ref = a13_rt_find_class(env, "com/blint/a13/rt/RtSret");
    if (ref.cls == NULL) {
        return;
    }
    env->RegisterNatives(ref.cls, &method, 1);
}

/* the pair-passing shape with an sret call inside the callee */
struct a13_rt_pair {
    const JNINativeMethod *methods;
    jint count;
};

__attribute__((visibility("default"))) void a13_rt_register_pair(JNIEnv *env, a13_rt_pair pair);

__attribute__((noinline)) static void a13_rt_register_via_pair(JNIEnv *env)
{
    JNINativeMethod methods[2];
    methods[0].name = a13_rt_one_name;
    methods[0].signature = a13_rt_one_sig;
    methods[0].fnPtr = a13_rt_fn((void *) a13_rt_one);
    methods[1].name = a13_rt_shared_name;
    methods[1].signature = a13_rt_shared_sig;
    methods[1].fnPtr = a13_rt_fn((void *) a13_rt_shared);
    a13_rt_pair pair = {methods, 2};
    a13_rt_register_pair(env, pair);
}

/* the refusal twin: two class names on the cold path decide nothing */
__attribute__((noinline)) static void a13_rt_register_two(JNIEnv *env)
{
    static jclass first_cls = NULL;
    static jclass second_cls = NULL;
    JNINativeMethod method;
    method.name = a13_rt_one_name;
    method.signature = a13_rt_one_sig;
    method.fnPtr = a13_rt_fn((void *) a13_rt_one);
    if (__builtin_expect(first_cls == NULL, 0)) {
        first_cls = env->FindClass("com/blint/a13/rt/RtTwoFirst");
        second_cls = env->FindClass("com/blint/a13/rt/RtTwo");
        if (first_cls == NULL || second_cls == NULL) {
            return;
        }
    }
    env->RegisterNatives(second_cls, &method, 1);
}

/* a static-table control beside them: must keep binding */
__attribute__((visibility("default"))) jint a13_rt_static_add(JNIEnv *env, jobject thiz, jint x)
{
    (void) env;
    (void) thiz;
    return x + 3;
}

static const JNINativeMethod a13_rt_static_table[] = {
    {"rtStaticAdd", "(I)I", (void *) a13_rt_static_add},
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void) reserved;
    JNIEnv *env = NULL;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    a13_rt_register_lazy(env);
    a13_rt_register_sret(env);
    a13_rt_register_via_pair(env);
    a13_rt_register_two(env);
    jclass cls = env->FindClass("com/blint/a13/rt/RtControl");
    if (cls != NULL) {
        env->RegisterNatives(cls, a13_rt_static_table, 1);
    }
    return JNI_VERSION_1_6;
}
