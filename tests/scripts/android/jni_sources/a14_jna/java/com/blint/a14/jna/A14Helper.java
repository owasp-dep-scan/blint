package com.blint.a14.jna;

import com.sun.jna.Native;

/**
 * The helper form (uniffi's findLibraryName shape): the name reaches the
 * call as a helper's returned constant, behind a property override. A
 * second library (liba14other.so) exports the same method name, so only
 * the constant can pick the right exporter.
 */
public final class A14Helper {
    static {
        Native.register(A14Helper.class, findLibraryName());
    }

    private static String findLibraryName() {
        String override = System.getProperty("a14.libraryOverride");
        if (override != null) {
            return override;
        }
        return "a14jna";
    }

    public static native int a14_helper_mul(int a, int b);

    private A14Helper() {}
}
