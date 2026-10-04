/*
 * The merged registration tables, in the TU that only DECLARES the
 * symbols a8_hybrid_defs.cpp defines. Two classes' tables plus one decoy
 * structure land in one .data.rel.ro run, the way the linker merges the
 * react-native codegen's per-class tables:
 *
 *   - name words: plain string literals -> local .rodata -> R_*_RELATIVE;
 *   - signature + fnPtr words: the extern symbols -> R_*_ABS* against the
 *     defined dynsym symbol (the fbjni shape the RELATIVE-only walk
 *     cannot see).
 *
 * The source tables below ARE the oracle; the tests assert the recovery
 * equals them.
 */
#include <jni.h>

extern "C" {
extern const char a8_hyb_sig_tick[];
extern const char a8_hyb_sig_name[];
extern const char a8_hyb_sig_init[];
extern const char a8_hyb_sig_pair[];
extern const char a8_hyb_sig_other_tick[];
extern const char a8_hyb_decoy_sig[];
extern const jlong a8_hyb_decoy_words[];
void a8_hyb_first_tick_call(JNIEnv *, jobject, jlong);
jstring a8_hyb_first_name_call(JNIEnv *, jobject, jstring);
jobject a8_hyb_first_init_call(JNIEnv *, jclass);
jint a8_hyb_other_pair_call(JNIEnv *, jobject, jint, jint);
jlong a8_hyb_other_tick_call(JNIEnv *, jobject, jlong);
}

// com.blint.a8.HybridFirst - a HybridClass table (initHybrid + members).
static const JNINativeMethod a8_first_methods[] = {
    {"hybInit", a8_hyb_sig_init, (void *) a8_hyb_first_init_call},
    {"hybTick", a8_hyb_sig_tick, (void *) a8_hyb_first_tick_call},
    {"hybName", a8_hyb_sig_name, (void *) a8_hyb_first_name_call},
};

// com.blint.a8.HybridOther - a second class, registered the same way.
static const JNINativeMethod a8_other_methods[] = {
    {"hybPair", a8_hyb_sig_pair, (void *) a8_hyb_other_pair_call},
    {"hybTick", a8_hyb_sig_other_tick, (void *) a8_hyb_other_tick_call},
};

/*
 * The refused neighbour: name and signature words that relocate like a
 * table's, but the "fnPtr" word targets an OBJECT in .rodata (the decoy
 * array) - not a function start, so the walk must reject the triple. The
 * never-taken registration keeps the array alive through --gc-sections.
 */
static const JNINativeMethod a8_decoy_methods[] = {
    {"hybDecoy", a8_hyb_decoy_sig, (void *) a8_hyb_decoy_words},
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void) reserved;
    JNIEnv *env = NULL;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    jclass first = env->FindClass("com/blint/a8/HybridFirst");
    if (first == NULL) {
        return JNI_ERR;
    }
    if (env->RegisterNatives(first, a8_first_methods, sizeof(a8_first_methods) / sizeof(a8_first_methods[0])) != JNI_OK) {
        return JNI_ERR;
    }
    jclass other = env->FindClass("com/blint/a8/HybridOther");
    if (other == NULL) {
        return JNI_ERR;
    }
    if (env->RegisterNatives(other, a8_other_methods, sizeof(a8_other_methods) / sizeof(a8_other_methods[0])) != JNI_OK) {
        return JNI_ERR;
    }
    if (reserved == (void *) 0xdeadbeef) {
        // Never taken; keeps the decoy array reachable for --gc-sections.
        env->RegisterNatives(other, a8_decoy_methods, sizeof(a8_decoy_methods) / sizeof(a8_decoy_methods[0]));
    }
    return JNI_VERSION_1_6;
}
