package com.blint.a14.jna;

import com.sun.jna.Native;

/** The init-chain form: the register call sits in a method the <clinit> runs. */
public final class A14ViaInit {
    static {
        ensureRegistered();
    }

    private static void ensureRegistered() {
        Native.register(A14ViaInit.class, "a14jna");
    }

    public static native int a14_via_init(int x);

    private A14ViaInit() {}
}
