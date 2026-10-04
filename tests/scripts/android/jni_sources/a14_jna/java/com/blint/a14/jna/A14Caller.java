package com.blint.a14.jna;

/**
 * The caller of another class's registrar: its <clinit> runs
 * A14SelfRegistrar.ensure(), which registers A14SelfRegistrar - JNA binds
 * that class's natives, never this one's. Its own declaration (whose name
 * the library exports) must stay unbound.
 */
public final class A14Caller {
    static {
        A14SelfRegistrar.ensure();
    }

    public static native int a14_caller_decoy(int x);

    private A14Caller() {}
}
