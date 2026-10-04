/*
 * The two honest 32-bit refusals the corpus showed, each pinned next to a
 * control that must keep binding (see GapNative.java for every entry's
 * expected fate, and a10_gap_nounwind.cpp for the wrapper without unwind
 * tables).
 *
 * plainAdd    control: a constant-initialized table -> binds on every ABI.
 * weakOnly    the fbjni kDescriptor shape: the signature word references a
 *             weak preemptible OBJECT dynsym, so the linker cannot fold the
 *             word to RELATIVE and the defined-symbol relocation map must
 *             read it - on REL ABIs too.
 * nounwindAdd a static triple whose fnPtr relocates correctly onto a real
 *             function that carries no unwind entry and no dynamic symbol
 *             (the RnHello v7a yoga wrappers) - no oracle-verifiable start,
 *             so the recovery must refuse the triple on every ABI.
 * smallOnly   the registrar builds the entry at run time through a noinline
 *             constructor (the fbjni makeNativeMethod shape on the ABIs
 *             where clang materializes small aggregates inline): no static
 *             triple exists, the declaration stays unbound.
 * decoyDataFn the adjacent refused shape: name and signature words that
 *             relocate like a table's, fnPtr against a defined OBJECT.
 */
#include <jni.h>

extern "C" __attribute__((visibility("hidden"))) jint
a10_nounwind_add(JNIEnv *env, jobject thiz, jint x);

__attribute__((visibility("default"))) jint
a10_plain_add(JNIEnv *env, jobject thiz, jint x)
{
    (void) env;
    (void) thiz;
    return x + 1;
}

/* Weak and preemptible, exactly fbjni's jmethod_traits<F>::kDescriptor:
 * defined here, exported, so the table's signature word relocates against
 * the symbol instead of folding to a relative relocation. */
extern "C" __attribute__((weak, visibility("default"))) const char a10_weak_descriptor[] = "(I)I";

__attribute__((visibility("default"))) jint
a10_small_impl(JNIEnv *env, jobject thiz, jint x)
{
    (void) env;
    (void) thiz;
    return x + 2;
}

/* An exported OBJECT, not a function: the decoy fnPtr's legal target. */
extern "C" __attribute__((visibility("default"))) jint a10_decoy_data = 7;

static const JNINativeMethod a10_weak_table[] = {
    {"weakOnly", a10_weak_descriptor, (void *) a10_small_impl},
};

static const JNINativeMethod a10_nounwind_table[] = {
    {"nounwindAdd", "(I)I", (void *) a10_nounwind_add},
};

static const JNINativeMethod a10_decoy_table[] = {
    {"decoyDataFn", "(I)I", (void *) &a10_decoy_data},
};

/* noinline so the entry is constructed by stores at run time, never emitted
 * as static data - the makeNativeMethod shape */
__attribute__((noinline)) static JNINativeMethod
a10_make_method(const char *name, const char *signature, void *fn)
{
    JNINativeMethod method;
    method.name = name;
    method.signature = signature;
    method.fnPtr = fn;
    return method;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void) reserved;
    JNIEnv *env = NULL;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    jclass cls = env->FindClass("com/blint/a10/gap/GapNative");
    if (cls == NULL) {
        return JNI_ERR;
    }
    JNINativeMethod plain[1] = {{"plainAdd", "(I)I", (void *) a10_plain_add}};
    if (env->RegisterNatives(cls, plain, 1) != JNI_OK) {
        return JNI_ERR;
    }
    if (env->RegisterNatives(cls, a10_weak_table, 1) != JNI_OK) {
        return JNI_ERR;
    }
    if (env->RegisterNatives(cls, a10_nounwind_table, 1) != JNI_OK) {
        return JNI_ERR;
    }
    JNINativeMethod small[1];
    small[0] = a10_make_method("smallOnly", a10_weak_descriptor, (void *) a10_small_impl);
    if (env->RegisterNatives(cls, small, 1) != JNI_OK) {
        return JNI_ERR;
    }
    if (reserved == (void *) 0xdeadbeef) {
        /* Never taken; keeps the decoy table reachable for --gc-sections. */
        env->RegisterNatives(cls, a10_decoy_table, 1);
    }
    return JNI_VERSION_1_6;
}
