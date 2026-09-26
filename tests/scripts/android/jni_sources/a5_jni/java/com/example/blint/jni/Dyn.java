package com.example.blint.jni;

/** Registered dynamically by libjnidyn.so's JNI_OnLoad (RegisterNatives). */
public class Dyn {
    static { System.loadLibrary("jnidyn"); }

    public static native int dynA1(int x);
    public static native String dynA2(String s);
    public static native int dynA3(int a, int b);

    public static int call() { return dynA1(1) + dynA2("x").length() + dynA3(2, 3); }
}
