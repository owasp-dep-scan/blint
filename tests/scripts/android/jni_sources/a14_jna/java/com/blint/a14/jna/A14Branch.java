package com.blint.a14.jna;

import com.sun.jna.Native;

/**
 * The branch-chosen name: each path passes a different constant, so no
 * one constant names the library. Both libraries export the method name,
 * so the row must stay ambiguous with both exporters listed.
 */
public final class A14Branch {
    private static final boolean OTHER = Boolean.getBoolean("a14.branch.other");

    static {
        String name;
        if (OTHER) {
            name = "a14other";
        } else {
            name = "a14jna";
        }
        Native.register(A14Branch.class, name);
    }

    public static native int a14_branch(int x);

    private A14Branch() {}
}
