#include <unistd.h>
/*
 * A5 E0 - statically registered JNI natives, one export per mangling
 * escape in the JNI spec's "Resolving Native Method Names" (Java SE 24):
 *
 *   NativeEscapes.plain_one   -> _1   (underscore in the method name)
 *   NativeEscapes.f(int)/f(String) -> __I / __Ljava_lang_String_2
 *                                    (overloads carry the __<sig> form,
 *                                     the String descriptor ends in _2)
 *   NativeEscapes.g(int[])    -> ___3I ([ in the descriptor -> _3)
 *   Nested.Inner.deep         -> _00024 ($ in the binary name -> _0xxxx)
 *   native_lib.Pkg.util       -> _1   (underscore in the package name)
 *   NativeEscapes.orphan      -> exported with no dex declaration
 *                                 (the undeclared_exports side of the join)
 *
 * missingNative is declared in NativeEscapes.java with no implementation
 * anywhere (the unbound_dex_natives side).
 *
 * Symbol-name oracle (JNI spec, Java SE 24, design.html ch.2):
 *   Java_ + escaped binary name ( / -> _ ) + _ + escaped method name
 *   + (__ + escaped parameter descriptor when the declaration is overloaded)
 *   escapes: _ -> _1, ; -> _2, [ -> _3, other non-alphanumeric-ASCII
 *   UTF-16 unit \uWXYZ -> _0wxyz (lowercase hex; $ = U+0024 -> _00024).
 */

#include <jni.h>

jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void) vm;
    (void) reserved;
    return JNI_VERSION_1_6;
}

void JNI_OnUnload(JavaVM *vm, void *reserved)
{
    (void) vm;
    (void) reserved;
}

/* NativeEscapes.plain_one(int) - underscore escaped as _1. */
JNIEXPORT jint JNICALL
Java_com_example_blint_jni_NativeEscapes_plain_1one(JNIEnv *env, jobject thiz, jint x)
{
    (void) env;
    (void) thiz;
    return x + 1;
}

/* NativeEscapes.f(int) and f(String) - the overloaded __<sig> forms. */
JNIEXPORT jint JNICALL
Java_com_example_blint_jni_NativeEscapes_f__I(JNIEnv *env, jobject thiz, jint i)
{
    (void) env;
    (void) thiz;
    return i * 2;
}

JNIEXPORT jint JNICALL
Java_com_example_blint_jni_NativeEscapes_f__Ljava_lang_String_2(
    JNIEnv *env, jobject thiz, jstring s)
{
    (void) thiz;
    const char *utf = (*env)->GetStringUTFChars(env, s, NULL);
    jint out = (jint) __builtin_strlen(utf);
    (*env)->ReleaseStringUTFChars(env, s, utf);
    return out;
}

/* NativeEscapes.g(int[]) - descriptor "[I" escapes the bracket as _3. */
JNIEXPORT jint JNICALL
Java_com_example_blint_jni_NativeEscapes_g___3I(JNIEnv *env, jobject thiz, jintArray a)
{
    (void) env;
    (void) thiz;
    return (*env)->GetArrayLength(env, a);
}

/* Nested.inner(int) - plain name on the outer class. */
JNIEXPORT jint JNICALL
Java_com_example_blint_jni_Nested_inner(JNIEnv *env, jobject thiz, jint x)
{
    (void) env;
    (void) thiz;
    return x + 3;
}

/* Nested$Inner.deep(String) - '$' is non-alphanumeric ASCII -> _00024. */
JNIEXPORT jint JNICALL
Java_com_example_blint_jni_Nested_00024Inner_deep(JNIEnv *env, jobject thiz, jstring s)
{
    (void) env;
    (void) thiz;
    const char *utf = (*env)->GetStringUTFChars(env, s, NULL);
    jint out = (jint) __builtin_strlen(utf);
    (*env)->ReleaseStringUTFChars(env, s, utf);
    return out + 5;
}

/* com.example.blint.native_lib.Pkg.util(int) - package underscore -> _1. */
JNIEXPORT jint JNICALL
Java_com_example_blint_native_1lib_Pkg_util(JNIEnv *env, jobject thiz, jint x)
{
    (void) env;
    (void) thiz;
    return x * 7;
}

/* NativeEscapes.libcCall(int) - a direct imported-libc call (getpid via
 * the PLT), so the F2 end-to-end path demo has a real libc hop after the
 * JNI edge: Java caller -> dex native -> this function -> getpid. */
JNIEXPORT jint JNICALL
Java_com_example_blint_jni_NativeEscapes_libcCall(JNIEnv *env, jobject thiz, jint x)
{
    (void) env;
    (void) thiz;
    return getpid() + x;
}

/* NativeEscapes.flag(boolean) - boolean parameter and return, so the
 * dex node-name rendering pins the Z case (this LIEF renders it `bool`,
 * not `boolean`). */
JNIEXPORT jboolean JNICALL
Java_com_example_blint_jni_NativeEscapes_flag(JNIEnv *env, jobject thiz, jboolean b)
{
    (void) env;
    (void) thiz;
    return !b;
}

/* Exported with no dex declaration: the undeclared_exports side. */
JNIEXPORT jint JNICALL
Java_com_example_blint_jni_NativeEscapes_orphan(JNIEnv *env, jobject thiz, jint x)
{
    (void) env;
    (void) thiz;
    return x - 1;
}
