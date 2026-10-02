/*
 * A13 review - the held registration's consumed-name control.
 *
 *   Java_com_blint_a13_held_HeldNamed_nativeInit
 *       registers its first table into the jclass Java passed in (no class
 *       name precedes that call), then finds HeldNamed below it and
 *       registers a second table there. The one class name the function
 *       materializes sits below the first call, but the second call
 *       consumes it: the first table's class is unknown and must not be
 *       attributed to HeldNamed.
 */
#include <jni.h>

__attribute__((visibility("default"))) jint a13_held_one(JNIEnv *env, jobject thiz, jint x)
{
    (void) env;
    (void) thiz;
    return x + 1;
}

__attribute__((visibility("default"))) jint a13_held_two(JNIEnv *env, jobject thiz, jint x)
{
    (void) env;
    (void) thiz;
    return x + 2;
}

static const char a13_held_one_name[] = "heldOne";
static const char a13_held_two_name[] = "heldTwo";
__attribute__((visibility("default"))) const char a13_held_sig[] = "(I)I";

/* noinline identity: the fnPtr word is a run-time value, never a static one */
__attribute__((noinline)) static void *a13_held_fn(void *fn)
{
    return fn;
}

extern "C" JNIEXPORT void JNICALL Java_com_blint_a13_held_HeldNamed_nativeInit(JNIEnv *env,
                                                                              jclass given)
{
    JNINativeMethod first;
    first.name = a13_held_one_name;
    first.signature = a13_held_sig;
    first.fnPtr = a13_held_fn((void *) a13_held_one);
    if (env->RegisterNatives(given, &first, 1) != 0) {
        return;
    }
    jclass named = env->FindClass("com/blint/a13/held/HeldNamed");
    if (named == NULL) {
        return;
    }
    JNINativeMethod second;
    second.name = a13_held_two_name;
    second.signature = a13_held_sig;
    second.fnPtr = a13_held_fn((void *) a13_held_two);
    env->RegisterNatives(named, &second, 1);
}
