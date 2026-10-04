/*
 * Three classes registering the SAME name + signature through
 * FindClass:
 *
 *   com.blint.a8.AmbigOne   - constant class name beside RegisterNatives
 *   com.blint.a8.AmbigTwo   - constant class name beside RegisterNatives
 *   com.blint.a8.AmbigThree - class name COMPOSED at runtime (snprintf),
 *                             so no constant names it: stays ambiguous
 *
 * The oracle: One and Two must bind to their own table's entry;
 * Three must stay ambiguous.
 */
#include <jni.h>
#include <stdio.h>

extern "C" {
extern const char a8_amb_sig_shared[];
extern const char a8_amb_sig_one[];
extern const char a8_amb_sig_two[];
extern const char a8_amb_sig_three[];
jstring a8_amb_shared_one(JNIEnv *, jobject, jlong);
jstring a8_amb_shared_two(JNIEnv *, jobject, jlong);
jstring a8_amb_shared_three(JNIEnv *, jobject, jlong);
jint a8_amb_one_only(JNIEnv *, jobject, jint);
jlong a8_amb_two_only(JNIEnv *, jobject, jlong);
void a8_amb_three_only(JNIEnv *, jobject, jstring);
}

static const JNINativeMethod a8_amb_one_methods[] = {
    {"sharedTick", a8_amb_sig_shared, (void *) a8_amb_shared_one},
    {"oneOnly", a8_amb_sig_one, (void *) a8_amb_one_only},
};

static const JNINativeMethod a8_amb_two_methods[] = {
    {"sharedTick", a8_amb_sig_shared, (void *) a8_amb_shared_two},
    {"twoOnly", a8_amb_sig_two, (void *) a8_amb_two_only},
};

static const JNINativeMethod a8_amb_three_methods[] = {
    {"sharedTick", a8_amb_sig_shared, (void *) a8_amb_shared_three},
    {"threeOnly", a8_amb_sig_three, (void *) a8_amb_three_only},
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void) reserved;
    JNIEnv *env = NULL;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    jclass one = env->FindClass("com/blint/a8/AmbigOne");
    if (one == NULL) {
        return JNI_ERR;
    }
    if (env->RegisterNatives(one, a8_amb_one_methods, sizeof(a8_amb_one_methods) / sizeof(a8_amb_one_methods[0])) != JNI_OK) {
        return JNI_ERR;
    }
    jclass two = env->FindClass("com/blint/a8/AmbigTwo");
    if (two == NULL) {
        return JNI_ERR;
    }
    if (env->RegisterNatives(two, a8_amb_two_methods, sizeof(a8_amb_two_methods) / sizeof(a8_amb_two_methods[0])) != JNI_OK) {
        return JNI_ERR;
    }
    // The third registration names its class at runtime. g_suffix is a
    // volatile read, so the composition cannot be constant-folded into a
    // memcpy of the full class name - no adrp+add (or lea) ever
    // materializes "com/blint/a8/AmbigThree" as one constant string.
    static volatile int g_suffix = 3;
    char composed[64];
    snprintf(composed, sizeof composed, "com/blint/a8/Ambig%d", g_suffix);
    jclass three = env->FindClass(composed);
    if (three == NULL) {
        return JNI_ERR;
    }
    if (env->RegisterNatives(three, a8_amb_three_methods, sizeof(a8_amb_three_methods) / sizeof(a8_amb_three_methods[0])) != JNI_OK) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}
