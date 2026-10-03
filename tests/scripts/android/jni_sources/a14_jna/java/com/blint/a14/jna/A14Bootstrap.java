package com.blint.a14.jna;

import com.sun.jna.Native;

/**
 * The cross-class registrar boundary: this class registers another class,
 * not itself, so the site is evidence for no class - its own decoy
 * declaration (whose name the library exports) must stay unbound, and so
 * must the registered class's own declaration (its <clinit> never
 * invokes register).
 */
public final class A14Bootstrap {
    static {
        Native.register(A14RegisteredByBootstrap.class, "a14jna");
    }

    public static native int a14_bootstrap_decoy(int x);

    private A14Bootstrap() {}
}
