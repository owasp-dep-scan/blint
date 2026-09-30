package com.blint.a9.split;

/**
 * A9 P3 - one merged JNINativeMethod table registered piecemeal through
 * per-class registrars, the fbjni registerNatives/registerHybrid shape.
 *
 * The table's five entries, in order:
 *   [0] oneOnly      - SplitOne only   (unique pair: binds without help)
 *   [1] splitShared  - SplitOne's slice, registrar count 2
 *   [2] splitShared  - SplitTwo's slice, registrar count 2
 *   [3] twoOnly      - SplitTwo only   (unique pair)
 *   [4] splitShared  - SplitRt's slice, count read from a volatile int
 *
 * Each registrar stack-copies its slice and calls a noinline per-class
 * helper that FindClass's its own constant name and makes the
 * RegisterNatives vtable call - the methods pointer the callee registers
 * is the caller's stack copy, so the carried-argument walk must tie it
 * back before the shared name can split by class. SplitRt's count is a
 * runtime load, so its registration carries no constant: entry [4] must
 * stay ambiguous.
 */
public class SplitNative {
    static {
        System.loadLibrary("a9split");
    }
}

class SplitOne {
    static {
        System.loadLibrary("a9split");
    }

    public static native int oneOnly(int x);

    public static native long splitShared(long when);
}

class SplitTwo {
    static {
        System.loadLibrary("a9split");
    }

    public static native long splitShared(long when);

    public static native long twoOnly(long y);
}

class SplitRt {
    static {
        System.loadLibrary("a9split");
    }

    public static native long splitShared(long when);
}
