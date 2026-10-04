package com.blint.a14.jna;

import com.sun.jna.Native;

/** Registers itself from a method another class's <clinit> runs: binds. */
public final class A14SelfRegistrar {
    static void ensure() {
        Native.register(A14SelfRegistrar.class, "a14jna");
    }

    public static native int a14_self_registrar(int x);

    private A14SelfRegistrar() {}
}
