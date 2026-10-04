/*
 * Tables built at run time, one registrar per shape (see
 * RtNative.java for each declaration's expected fate). The entry words are
 * built per field so no constant aggregate exists for the compiler to
 * place in .data.rel.ro: the name and signature are file-scope objects
 * reached through PIC (GOTOFF for the local ones, the GOT for the exported
 * signature), and the fnPtr goes through a noinline identity function so
 * it can never be folded into a static template. The 32-bit builds are the
 * measured fbjni shape (ThreadScope::OnLoad / ComponentFactory); the
 * same source on arm64/x86_64 gives the jni.hpp-style store sequence
 * maplibre ships on every ABI.
 */
#include <jni.h>

__attribute__((visibility("default"))) void a11_rt_register_aligned(JNIEnv *env);

/* fn implementations, exported so each ABI's own copy has verified starts */
__attribute__((visibility("default"))) jint a11_rt_one(JNIEnv *env, jobject thiz, jint x)
{
    (void) env;
    (void) thiz;
    return x + 1;
}

__attribute__((visibility("default"))) jlong a11_rt_shared_a(JNIEnv *env, jobject thiz, jlong t)
{
    (void) env;
    (void) thiz;
    return t + 1;
}

__attribute__((visibility("default"))) jlong a11_rt_shared_b(JNIEnv *env, jobject thiz, jlong t)
{
    (void) env;
    (void) thiz;
    return t + 2;
}

/* the entry words: local strings reach the registrar GOTOFF-relative; the
 * signature is exported so its address arrives through the GOT (fbjni's
 * kDescriptor placement). The extern declaration first: a C++ const at
 * namespace scope has internal linkage without it, and the other TU's GOT
 * reference would then name an undefined symbol. */
static const char a11_rt_one_name[] = "rtOne";
static const char a11_rt_shared_name[] = "rtShared";
extern const char a11_rt_one_sig[];
extern const char a11_rt_shared_sig[];
__attribute__((visibility("default"))) const char a11_rt_one_sig[] = "(I)I";
__attribute__((visibility("default"))) const char a11_rt_shared_sig[] = "(J)J";

/* noinline identity: the fnPtr word is a run-time value, never a static one */
__attribute__((noinline)) static void *a11_rt_fn(void *fn)
{
    return fn;
}

/* the pair-passing shape: an 8-byte {methods, count} aggregate handed to a
 * helper in another translation unit by value - the call crosses the PLT, so
 * the i386 build stages the pair on the stack the way fbjni's registerHybrid
 * receives its initializer_list. Defined in a11_rt_aligned.cpp. */
struct a11_rt_pair {
    const JNINativeMethod *methods;
    jint count;
};

__attribute__((visibility("default"))) void a11_rt_register_pair(JNIEnv *env, a11_rt_pair pair);
__attribute__((visibility("default"))) void a11_rt_register_pair_again(JNIEnv *env, a11_rt_pair pair);

__attribute__((noinline)) static void a11_rt_register_via_pair(JNIEnv *env)
{
    JNINativeMethod methods[2];
    methods[0].name = a11_rt_one_name;
    methods[0].signature = a11_rt_one_sig;
    methods[0].fnPtr = a11_rt_fn((void *) a11_rt_one);
    methods[1].name = a11_rt_shared_name;
    methods[1].signature = a11_rt_shared_sig;
    methods[1].fnPtr = a11_rt_fn((void *) a11_rt_shared_a);
    a11_rt_pair pair = {methods, 2};
    a11_rt_register_pair(env, pair);
    a11_rt_register_pair_again(env, pair);
}

/* volatile: the count stays a run-time value (the adjacent shape that must
 * stay unrecovered) */
static volatile jint a11_rt_volatile_count = 2;

/* a static-table control beside the runtime ones: must keep binding */
__attribute__((visibility("default"))) jint a11_rt_static_add(JNIEnv *env, jobject thiz, jint x)
{
    (void) env;
    (void) thiz;
    return x + 3;
}

static const JNINativeMethod a11_rt_static_table[] = {
    {"rtStaticAdd", "(I)I", (void *) a11_rt_static_add},
};

/* the registrar the walk can read: constant count, per-field stores */
__attribute__((noinline)) static void a11_rt_register_imm(JNIEnv *env)
{
    JNINativeMethod methods[2];
    methods[0].name = a11_rt_one_name;
    methods[0].signature = a11_rt_one_sig;
    methods[0].fnPtr = a11_rt_fn((void *) a11_rt_one);
    methods[1].name = a11_rt_shared_name;
    methods[1].signature = a11_rt_shared_sig;
    methods[1].fnPtr = a11_rt_fn((void *) a11_rt_shared_a);
    jclass cls = env->FindClass("com/blint/a11/rt/RtNative");
    if (cls == NULL) {
        return;
    }
    env->RegisterNatives(cls, methods, 2);
}

/* the adjacent shape: identical stores, a count read at run time */
__attribute__((noinline)) static void a11_rt_register_volatile(JNIEnv *env)
{
    JNINativeMethod methods[2];
    methods[0].name = a11_rt_one_name;
    methods[0].signature = a11_rt_one_sig;
    methods[0].fnPtr = a11_rt_fn((void *) a11_rt_one);
    methods[1].name = a11_rt_shared_name;
    methods[1].signature = a11_rt_shared_sig;
    methods[1].fnPtr = a11_rt_fn((void *) a11_rt_shared_b);
    jclass cls = env->FindClass("com/blint/a11/rt/RtVolatile");
    if (cls == NULL) {
        return;
    }
    env->RegisterNatives(cls, methods, a11_rt_volatile_count);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void) reserved;
    JNIEnv *env = NULL;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    a11_rt_register_imm(env);
    a11_rt_register_via_pair(env);
    a11_rt_register_volatile(env);
    a11_rt_register_aligned(env);
    jclass cls = env->FindClass("com/blint/a11/rt/RtStatic");
    if (cls != NULL) {
        env->RegisterNatives(cls, a11_rt_static_table, 1);
    }
    return JNI_VERSION_1_6;
}
