package com.example.blint.jni;

/** Static natives: every mangling escape has a declaration here, plus one
 *  method (missingNative) with no implementation in any library. */
public class NativeEscapes {
    static { System.loadLibrary("jnistat"); }

    public static native int plain_one(int x);
    public static native int f(int i);
    public static native int f(String s);
    public static native int g(int[] a);
    public static native int missingNative(int x);
    public static native int libcCall(int x);

    public static int callThem() {
        int[] one = {1, 2, 3};
        return plain_one(1) + f(2) + f("three") + g(one) + libcCall(4);
    }
}
