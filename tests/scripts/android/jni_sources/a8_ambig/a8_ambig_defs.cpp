/*
 * A8 N3 - the ambiguity fixture's shared symbols, in the fbjni shape
 * (preemptible dynsym definitions away from the tables that name them;
 * see a8_hybrid_defs.cpp). The three classes' tables all carry an entry
 * with the SAME name + signature - the shape that leaves the join's
 * dynamic binding ambiguous until the FindClass confirmer speaks.
 */
#include <jni.h>

extern "C" {

__attribute__((visibility("default"))) extern const char a8_amb_sig_shared[] =
    "(J)Ljava/lang/String;";
__attribute__((visibility("default"))) extern const char a8_amb_sig_one[] = "(I)I";
__attribute__((visibility("default"))) extern const char a8_amb_sig_two[] = "(J)J";
__attribute__((visibility("default"))) extern const char a8_amb_sig_three[] = "(Ljava/lang/String;)V";

__attribute__((visibility("default"))) jstring a8_amb_shared_one(
    JNIEnv *env,
    jobject thiz,
    jlong when)
{
    (void) thiz;
    (void) when;
    return env->NewStringUTF("one");
}

__attribute__((visibility("default"))) jstring a8_amb_shared_two(
    JNIEnv *env,
    jobject thiz,
    jlong when)
{
    (void) thiz;
    (void) when;
    return env->NewStringUTF("two");
}

__attribute__((visibility("default"))) jstring a8_amb_shared_three(
    JNIEnv *env,
    jobject thiz,
    jlong when)
{
    (void) thiz;
    (void) when;
    return env->NewStringUTF("three");
}

__attribute__((visibility("default"))) jint a8_amb_one_only(JNIEnv *env, jobject thiz, jint x)
{
    (void) env;
    (void) thiz;
    return x + 1;
}

__attribute__((visibility("default"))) jlong a8_amb_two_only(JNIEnv *env, jobject thiz, jlong y)
{
    (void) env;
    (void) thiz;
    return y + 2;
}

__attribute__((visibility("default"))) void a8_amb_three_only(JNIEnv *env, jobject thiz, jstring s)
{
    (void) env;
    (void) thiz;
    (void) s;
}

}  // extern "C"
