package com.blint.a14.jna;

import com.sun.jna.Native;

/**
 * The computed name: the register call's String argument is a static
 * field read, in a register that held the constant "a14jna" a few
 * instructions earlier. Nothing names the library, and both libraries
 * export the method name, so the row must stay ambiguous - the earlier
 * constant must not pick liba14jna.so.
 */
public final class A14Stale {
    private static String libraryName = System.getProperty("a14.stale.library");

    static {
        System.setProperty("a14.stale.marker", "a14jna");
        Native.register(A14Stale.class, libraryName);
    }

    public static native int a14_stale(int x);

    private A14Stale() {}
}
