package com.example.blint.native_lib;

/** A package with an underscore: native_1lib in the export. */
public class Pkg {
    static { System.loadLibrary("jnistat"); }

    public static native int util(int x);

    public static int call() { return util(8); }
}
