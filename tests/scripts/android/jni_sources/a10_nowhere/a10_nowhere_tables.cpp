/*
 * The "registered nowhere" mark (see NwNative.java for each
 * declaration's expected fate). One three-entry table:
 *
 *   [0] nwShared - registered for NwBound with a constant count, the
 *       registrar passing the static table's address directly, so the
 *       FindClass confirmer resolves exactly [T, T + stride) to
 *       com.blint.a10.nowhere.NwBound.
 *   [1] nwRt     - registered for NwRtA through a stack copy whose count
 *       is a volatile load: no constant, no resolved range.
 *   [2] nwRt     - the same shape for NwRtB.
 *   [3] nwMine   - registered for NwElsewhere with a constant count.
 *
 * NwMissing declares nwShared but no registrar anywhere names it: with
 * --disassemble its row must carry the registered-nowhere mark beside its
 * ambiguity; NwRtA and NwRtB's rows must stay plain ambiguous (their
 * candidates sit in no resolved range, so nothing is claimed about them).
 * NwElsewhere also declares nwShared - and a chain DOES name it, for its
 * own nwMine registration - so its nwShared row must stay ambiguous
 * without the mark even though its candidate is covered by NwBound's
 * range: "registered nowhere" claims no chain names the class at all.
 *
 * Each per-class helper FindClass's its own constant name (the confirmer
 * reads the materialized string in the callee, not an argument).
 */
#include <jni.h>
#include <string.h>

__attribute__((visibility("default"))) jint
a10_nw_bound(JNIEnv *env, jobject thiz, jint x)
{
    (void) env;
    (void) thiz;
    return x + 1;
}

__attribute__((visibility("default"))) jlong
a10_nw_rt_a(JNIEnv *env, jobject thiz, jlong t)
{
    (void) env;
    (void) thiz;
    return t + 1;
}

__attribute__((visibility("default"))) jlong
a10_nw_rt_b(JNIEnv *env, jobject thiz, jlong t)
{
    (void) env;
    (void) thiz;
    return t + 2;
}

__attribute__((visibility("default"))) jlong
a10_nw_mine(JNIEnv *env, jobject thiz, jlong t)
{
    (void) env;
    (void) thiz;
    return t + 3;
}

static const JNINativeMethod a10_nw_table[] = {
    {"nwShared", "(I)I", (void *) a10_nw_bound},
    {"nwRt", "(J)J", (void *) a10_nw_rt_a},
    {"nwRt", "(J)J", (void *) a10_nw_rt_b},
    {"nwMine", "(J)J", (void *) a10_nw_mine},
};

/* volatile: the count must stay a runtime value in the compiled code */
static volatile jint a10_nw_rt_count = 1;

__attribute__((noinline)) static jboolean a10_nw_register_bound(
    JNIEnv *env, const JNINativeMethod *methods, jint count)
{
    jclass cls = env->FindClass("com/blint/a10/nowhere/NwBound");
    if (cls == NULL) {
        return JNI_ERR;
    }
    return env->RegisterNatives(cls, methods, count);
}

__attribute__((noinline)) static jboolean a10_nw_register_rt_a(
    JNIEnv *env, const JNINativeMethod *methods, jint count)
{
    jclass cls = env->FindClass("com/blint/a10/nowhere/NwRtA");
    if (cls == NULL) {
        return JNI_ERR;
    }
    return env->RegisterNatives(cls, methods, count);
}

__attribute__((noinline)) static jboolean a10_nw_register_rt_b(
    JNIEnv *env, const JNINativeMethod *methods, jint count)
{
    jclass cls = env->FindClass("com/blint/a10/nowhere/NwRtB");
    if (cls == NULL) {
        return JNI_ERR;
    }
    return env->RegisterNatives(cls, methods, count);
}

__attribute__((noinline)) static jboolean a10_nw_register_elsewhere(
    JNIEnv *env, const JNINativeMethod *methods, jint count)
{
    jclass cls = env->FindClass("com/blint/a10/nowhere/NwElsewhere");
    if (cls == NULL) {
        return JNI_ERR;
    }
    return env->RegisterNatives(cls, methods, count);
}

__attribute__((noinline)) static void a10_nw_do_bound(JNIEnv *env)
{
    a10_nw_register_bound(env, a10_nw_table, 1);
}

__attribute__((noinline)) static void a10_nw_do_rt_a(JNIEnv *env)
{
    JNINativeMethod copy[1];
    memcpy(copy, a10_nw_table + 1, sizeof copy);
    a10_nw_register_rt_a(env, copy, a10_nw_rt_count);
}

__attribute__((noinline)) static void a10_nw_do_rt_b(JNIEnv *env)
{
    JNINativeMethod copy[1];
    memcpy(copy, a10_nw_table + 2, sizeof copy);
    a10_nw_register_rt_b(env, copy, a10_nw_rt_count);
}

__attribute__((noinline)) static void a10_nw_do_elsewhere(JNIEnv *env)
{
    a10_nw_register_elsewhere(env, a10_nw_table + 3, 1);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void) reserved;
    JNIEnv *env = NULL;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    a10_nw_do_bound(env);
    a10_nw_do_rt_a(env);
    a10_nw_do_rt_b(env);
    a10_nw_do_elsewhere(env);
    return JNI_VERSION_1_6;
}
