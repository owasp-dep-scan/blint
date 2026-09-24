#include <jni.h>
#include <string.h>
#include <stdlib.h>

/* Tier-1 planted fixture: a plain dynamic JNI library. Built by the real NDK
 * toolchain (ndk-build); ground truth for the built .so is captured in the
 * same run with llvm-readelf from the same NDK. */

/* blint_sink (blint_sink.c) keeps the canary-planted buffer's address
 * escaping the function so the stack-protector import survives -O2. */
void blint_sink(void *p, size_t n);

static jstring counter_strings[4] = {0};

jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void)vm;
    (void)reserved;
    return JNI_VERSION_1_6;
}

/* Non-static export with a plain symbol name so symbol-based reviews have a
 * known answer; malloc/copy give the imports a known answer too. */
jint java_add_left(jint a, jint b)
{
    volatile jint r = a + b;
    /* A char array whose address escapes: with -fstack-protector-strong this
     * plants the canary import (__stack_chk_fail) with a known answer. */
    char buf[64];
    memset(buf, 0, sizeof(buf));
    buf[0] = (char)r;
    blint_sink(buf, sizeof(buf));
    return r + buf[0];
}

JNIEXPORT jstring JNICALL
Java_com_example_blint_fixtures_Hello_stringFromJNI(JNIEnv *env, jobject thiz)
{
    (void)thiz;
    if (!counter_strings[0]) {
        const char *msg = "hello from blint tier-1";
        counter_strings[0] = (*env)->NewStringUTF(env, msg);
    }
    return counter_strings[0];
}
