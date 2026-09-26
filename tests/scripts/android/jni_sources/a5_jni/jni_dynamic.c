/*
 * A5 E0/F1 - dynamic registration: five methods across two classes,
 * registered from JNI_OnLoad through RegisterNatives.
 *
 * The JNINativeMethod arrays are `static const` with relocated pointers
 * (name/signature string addresses, function addresses), so a PIE NDK
 * build lands them in .data.rel.ro with R_*_RELATIVE relocations - the
 * table shape F1 recovers without disassembly.
 *
 * jni.h constants (NDK r28c 28.2.13676358 sysroot, jni.h):
 *   JNINativeMethod {const char *name; const char *signature; void *fnPtr;}
 *     at lines 128-131;
 *   RegisterNatives is slot 215 of struct JNINativeInterface (line 149;
 *   the pointer declaration at line 454, preceded by 215 members
 *   including reserved0-3), i.e. JNIEnv offset 215 * sizeof(void*).
 */

#include <jni.h>

static jint dyn_a1(JNIEnv *env, jobject thiz, jint x)
{
    (void) env;
    (void) thiz;
    return x + 11;
}

static jstring dyn_a2(JNIEnv *env, jobject thiz, jstring s)
{
    (void) thiz;
    return (*env)->NewStringUTF(env, "a2");
}

static jint dyn_a3(JNIEnv *env, jobject thiz, jint a, jint b)
{
    (void) env;
    (void) thiz;
    return a + b + 13;
}

static jint dyn_b1(JNIEnv *env, jobject thiz, jint x)
{
    (void) env;
    (void) thiz;
    return x * 17;
}

static jint dyn_b2(JNIEnv *env, jobject thiz, jlong y)
{
    (void) env;
    (void) thiz;
    return (jint) (y % 19);
}

static const JNINativeMethod dyn_a_methods[] = {
    {"dynA1", "(I)I", (void *) dyn_a1},
    {"dynA2", "(Ljava/lang/String;)Ljava/lang/String;", (void *) dyn_a2},
    {"dynA3", "(II)I", (void *) dyn_a3},
};

static const JNINativeMethod dyn_b_methods[] = {
    {"dynB1", "(I)I", (void *) dyn_b1},
    {"dynB2", "(J)I", (void *) dyn_b2},
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void) reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    jclass class_a = (*env)->FindClass(env, "com/example/blint/jni/Dyn");
    if (class_a == NULL) {
        return JNI_ERR;
    }
    if ((*env)->RegisterNatives(env, class_a, dyn_a_methods,
                                sizeof(dyn_a_methods) / sizeof(dyn_a_methods[0])) != JNI_OK) {
        return JNI_ERR;
    }
    jclass class_b = (*env)->FindClass(env, "com/example/blint/jni/DynB");
    if (class_b == NULL) {
        return JNI_ERR;
    }
    if ((*env)->RegisterNatives(env, class_b, dyn_b_methods,
                                sizeof(dyn_b_methods) / sizeof(dyn_b_methods[0])) != JNI_OK) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}
