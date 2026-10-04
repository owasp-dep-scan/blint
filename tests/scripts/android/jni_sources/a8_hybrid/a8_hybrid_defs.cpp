/*
 * The fbjni "merged registration" shape: the signature descriptors
 * and the wrapper entry points live in THIS translation unit as preemptible
 * dynsym symbols (default visibility), while the tables that name them
 * live in a8_hybrid_tables.cpp. A -fPIC -shared NDK link then emits
 * R_*_ABS* relocations against the symbols for the signature and fnPtr
 * words instead of folding them to R_*_RELATIVE - the exact relocation
 * shape libreactnative.so's fbjni tables carry (jmethod_traits<F>::
 * kDescriptor OBJECT symbols and MethodWrapper<>::call / FunctionWrapper-
 * WithJniEntryPoint<>::call FUNC symbols, all weak, all defined in .dynsym).
 *
 * The classes registered here mirror one fbjni HybridClass: a static
 * accessor (FunctionWrapperWithJniEntryPoint shape) and member methods
 * (MethodWrapper shape).
 */
#include <jni.h>

extern "C" {

// jmethod_traits<F>::kDescriptor analogues: exported const descriptors.
__attribute__((visibility("default"))) extern const char a8_hyb_sig_tick[] = "(J)V";
__attribute__((visibility("default"))) extern const char a8_hyb_sig_name[] =
    "(Ljava/lang/String;)Ljava/lang/String;";
__attribute__((visibility("default"))) extern const char a8_hyb_sig_init[] =
    "()Lcom/blint/a8/HybridFirst;";
__attribute__((visibility("default"))) extern const char a8_hyb_sig_pair[] = "(II)I";
__attribute__((visibility("default"))) extern const char a8_hyb_sig_other_tick[] = "(J)J";

// MethodWrapper<M, &m>::call analogues: exported wrappers with the JNI
// entry point signature.
__attribute__((visibility("default"))) void a8_hyb_first_tick_call(
    JNIEnv *env, jobject thiz, jlong when)
{
    (void) env;
    (void) thiz;
    (void) when;
}

__attribute__((visibility("default"))) jstring a8_hyb_first_name_call(
    JNIEnv *env,
    jobject thiz,
    jstring s)
{
    (void) thiz;
    return s != NULL ? s : env->NewStringUTF("first");
}

// FunctionWrapperWithJniEntryPoint<F>::call analogue (static accessor).
__attribute__((visibility("default"))) jobject a8_hyb_first_init_call(
    JNIEnv *env,
    jclass clazz)
{
    (void) env;
    (void) clazz;
    return NULL;
}

// The second class's methods: same wrapper shapes, distinct functions.
__attribute__((visibility("default"))) jint a8_hyb_other_pair_call(
    JNIEnv *env,
    jobject thiz,
    jint a,
    jint b)
{
    (void) env;
    (void) thiz;
    return a + b;
}

__attribute__((visibility("default"))) jlong a8_hyb_other_tick_call(
    JNIEnv *env,
    jobject thiz,
    jlong when)
{
    (void) env;
    (void) thiz;
    return when + 1;
}

/*
 * The adjacent FALSE shape (every acceptance needs a
 * refused neighbour): a descriptor + a "fnPtr" word that relocates against
 * a defined OBJECT symbol in .rodata, not a function. A vtable-ish pair
 * must not become a table entry.
 */
__attribute__((visibility("default"))) extern const char a8_hyb_decoy_sig[] = "(I)V";
__attribute__((visibility("default"))) extern const jlong a8_hyb_decoy_words[] = {
    static_cast<jlong>(0x1122334455667788ULL),
    static_cast<jlong>(0x99aabbccddeeff00ULL)};

}  // extern "C"
