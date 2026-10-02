package com.blint.a13.rt;

/**
 * A13 U1 - the lazy-class declaration. The registrar finds the class only
 * on the cold init path below the RegisterNatives call, so the runtime
 * walk pairs the call with the one class name the function materializes;
 * rtOne binds through runtime_table on the 32-bit ABIs and stays unbound
 * everywhere else.
 */
public class RtLazy {
    static {
        System.loadLibrary("a13rt");
    }

    public static native int rtOne(int x);
}
