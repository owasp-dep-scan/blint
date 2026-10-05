package com.blint.a14.jna;

import com.sun.jna.Native;

/** The direct form: the constant library name at the register call. */
public final class A14Direct {
    static {
        Native.register(A14Direct.class, "a14jna");
    }

    public static native int a14_direct_add(int a, int b);

    private A14Direct() {}
}
