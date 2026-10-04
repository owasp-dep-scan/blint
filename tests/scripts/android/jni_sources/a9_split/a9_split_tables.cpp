/*
 * The merged-table split fixture (see SplitNative.java for the
 * expected fate of each entry). The registrars and the per-class helpers
 * are noinline so the compiled shape keeps the registrar -> helper call
 * the carried-argument walk follows.
 */
#include <jni.h>
#include <string.h>

__attribute__((visibility("default"))) jint a9_split_one_only(JNIEnv *env, jobject thiz, jint x)
{
    (void) env;
    (void) thiz;
    return x + 1;
}

__attribute__((visibility("default"))) jlong a9_split_shared_one(JNIEnv *env, jobject thiz, jlong t)
{
    (void) env;
    (void) thiz;
    return t + 1;
}

__attribute__((visibility("default"))) jlong a9_split_shared_two(JNIEnv *env, jobject thiz, jlong t)
{
    (void) env;
    (void) thiz;
    return t + 2;
}

__attribute__((visibility("default"))) jlong a9_split_two_only(JNIEnv *env, jobject thiz, jlong y)
{
    (void) env;
    (void) thiz;
    return y + 2;
}

__attribute__((visibility("default"))) jlong a9_split_shared_rt(JNIEnv *env, jobject thiz, jlong t)
{
    (void) env;
    (void) thiz;
    return t + 3;
}

static const JNINativeMethod a9_split_table[] = {
    {"oneOnly", "(I)I", (void *) a9_split_one_only},
    {"splitShared", "(J)J", (void *) a9_split_shared_one},
    {"splitShared", "(J)J", (void *) a9_split_shared_two},
    {"twoOnly", "(J)J", (void *) a9_split_two_only},
    {"splitShared", "(J)J", (void *) a9_split_shared_rt},
};

/* volatile: the count must stay a runtime value in the compiled code */
static volatile jint a9_rt_count = 1;

__attribute__((noinline)) static jboolean a9_register_for_one(
    JNIEnv *env, const JNINativeMethod *methods, jint count)
{
    jclass cls = env->FindClass("com/blint/a9/split/SplitOne");
    if (cls == NULL) {
        return JNI_ERR;
    }
    return env->RegisterNatives(cls, methods, count);
}

__attribute__((noinline)) static jboolean a9_register_for_two(
    JNIEnv *env, const JNINativeMethod *methods, jint count)
{
    jclass cls = env->FindClass("com/blint/a9/split/SplitTwo");
    if (cls == NULL) {
        return JNI_ERR;
    }
    return env->RegisterNatives(cls, methods, count);
}

__attribute__((noinline)) static jboolean a9_register_for_rt(
    JNIEnv *env, const JNINativeMethod *methods, jint count)
{
    jclass cls = env->FindClass("com/blint/a9/split/SplitRt");
    if (cls == NULL) {
        return JNI_ERR;
    }
    return env->RegisterNatives(cls, methods, count);
}

__attribute__((noinline)) static void a9_register_one(JNIEnv *env)
{
    JNINativeMethod copy[2];
    memcpy(copy, a9_split_table, sizeof copy);
    a9_register_for_one(env, copy, 2);
}

__attribute__((noinline)) static void a9_register_two(JNIEnv *env)
{
    JNINativeMethod copy[2];
    memcpy(copy, a9_split_table + 2, sizeof copy);
    a9_register_for_two(env, copy, 2);
}

__attribute__((noinline)) static void a9_register_rt(JNIEnv *env)
{
    JNINativeMethod copy[1];
    memcpy(copy, a9_split_table + 4, sizeof copy);
    a9_register_for_rt(env, copy, a9_rt_count);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void) reserved;
    JNIEnv *env = NULL;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    a9_register_one(env);
    a9_register_two(env);
    a9_register_rt(env);
    return JNI_VERSION_1_6;
}
