package com.example.blint.jni;

/** Second dynamically-registered class. */
public class DynB {
    static { System.loadLibrary("jnidyn"); }

    public static native int dynB1(int x);
    public static native int dynB2(long y);

    public static int call() { return dynB1(5) + dynB2(6L); }
}
