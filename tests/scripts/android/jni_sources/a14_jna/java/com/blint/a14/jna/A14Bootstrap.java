package com.blint.a14.jna;

import com.sun.jna.Native;

/**
 * The cross-class registrar: this class registers another class by its
 * literal, not itself. JNA binds the registered class's natives, so
 * A14RegisteredByBootstrap's declaration binds, while this class's own
 * decoy declaration (whose name the library exports) must stay unbound.
 */
public final class A14Bootstrap {
    static {
        Native.register(A14RegisteredByBootstrap.class, "a14jna");
    }

    public static native int a14_bootstrap_decoy(int x);

    private A14Bootstrap() {}
}
