package com.blint.a14.jna;

import com.sun.jna.Native;

/**
 * The caller-class overload from a nested class: Init declares no
 * natives, so JNA registers the nearest enclosing class that does -
 * A14Outer, whose declaration binds.
 */
public final class A14Outer {
    static {
        Init.go();
    }

    public static native int a14_outer_fn(int x);

    private A14Outer() {}

    static final class Init {
        static void go() {
            Native.register("a14jna");
        }

        private Init() {}
    }
}
