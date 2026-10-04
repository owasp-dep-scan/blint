package com.blint.a14.jna;

import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;

/**
 * The ambiguity case: registered against the process library (JNA's
 * shape for "whatever already exports the name"), with the name exported
 * by two libraries in every ABI. No library name reaches the call, so
 * the row must stay ambiguous with both exporters listed.
 */
public final class A14Ambiguous {
    static {
        Native.register(A14Ambiguous.class, NativeLibrary.getProcess());
    }

    public static native int a14_ambiguous(int x);

    private A14Ambiguous() {}
}
