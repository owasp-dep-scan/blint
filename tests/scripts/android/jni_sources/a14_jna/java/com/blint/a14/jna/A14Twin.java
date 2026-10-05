package com.blint.a14.jna;

/**
 * The negative twin: the same native declarations, the same exports, but
 * no Native.register anywhere - System.loadLibrary is the JNI path and
 * binds nothing by plain name. Every declaration must stay unbound.
 */
public final class A14Twin {
    static {
        System.loadLibrary("a14jna");
    }

    public static native int a14_twin_echo(int x);

    private A14Twin() {}
}
