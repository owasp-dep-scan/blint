package com.example.blint.jni;

/** Nested class: the binary name carries '$' (-> _00024 in the export). */
public class Nested {
    static { System.loadLibrary("jnistat"); }

    public static native int inner(int x);

    public static class Inner {
        static { System.loadLibrary("jnistat"); }

        public static native int deep(String s);

        public static int call() { return inner(4) + deep("five"); }
    }
}
