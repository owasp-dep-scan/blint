/*
 * Three JNINativeMethod entries whose name/signature strings cross
 * the recovery's read bounds (see LongNative.java for the expected fate of
 * each). The descriptors are exact repetitions of the Child segment, so
 * they match the Java declarations byte for byte.
 */
#include <jni.h>

static void a9_long_sig_under(JNIEnv *env, jobject thiz, jobject p00, jobject p01, jobject p02, jobject p03, jobject p04, jobject p05, jobject p06, jobject p07, jobject p08, jobject p09, jobject p10, jobject p11, jobject p12, jobject p13, jobject p14, jobject p15, jobject p16)
{
    (void) env;
    (void) thiz;
}

static void a9_long_sig_long(JNIEnv *env, jobject thiz, jobject q00, jobject q01, jobject q02, jobject q03, jobject q04, jobject q05, jobject q06, jobject q07, jobject q08, jobject q09, jobject q10, jobject q11, jobject q12, jobject q13, jobject q14, jobject q15, jobject q16, jobject q17, jobject q18, jobject q19, jobject q20, jobject q21)
{
    (void) env;
    (void) thiz;
}

static jint a9_long_name_long(JNIEnv *env, jobject thiz, jint x)
{
    (void) env;
    (void) thiz;
    return x;
}

static const JNINativeMethod a9_long_methods[] = {
    {"sigUnder", "(Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;)V", (void *) a9_long_sig_under},
    {"sigLong", "(Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;Lcom/blint/a9/longpkg/LongNative$GrandParent$Parent$Child;)V", (void *) a9_long_sig_long},
    {"a9LongNameXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyz", "(I)I", (void *) a9_long_name_long},
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void) reserved;
    JNIEnv *env = NULL;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    jclass cls = env->FindClass("com/blint/a9/longpkg/LongNative");
    if (cls == NULL) {
        return JNI_ERR;
    }
    if (env->RegisterNatives(cls, a9_long_methods,
                             sizeof(a9_long_methods) / sizeof(a9_long_methods[0])) != JNI_OK) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}
