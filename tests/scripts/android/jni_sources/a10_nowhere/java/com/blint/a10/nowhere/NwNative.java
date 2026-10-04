package com.blint.a10.nowhere;

/**
 * The registered-nowhere mark.
 *
 * <ul>
 *   <li>NwBound.nwShared - binds through the FindClass confirmer (the
 *   registration names it with a constant count).</li>
 *   <li>NwMissing.nwShared - the same (name, signature) pair, so its row
 *   stays ambiguous; no registrar anywhere names NwMissing, and with
 *   --disassemble the row must carry the registered-nowhere mark.</li>
 *   <li>NwRtA.nwRt / NwRtB.nwRt - their candidates sit in no resolved
 *   range (volatile counts), so their rows stay plain ambiguous: the
 *   confirmer claims nothing about them, and no mark appears.</li>
 *   <li>NwElsewhere - declares nwShared (its row stays ambiguous because
 *   NwBound's range covers the only candidate) and nwMine, which its own
 *   registrar registers with a constant count. A chain names NwElsewhere,
 *   so its nwShared row must NOT carry the mark even though its candidate
 *   is covered: "registered nowhere" claims no chain names the class at
 *   all, and nwMine's registration names it.</li>
 * </ul>
 */
public class NwNative {
    static {
        System.loadLibrary("a10nowhere");
    }
}

class NwBound {
    static {
        System.loadLibrary("a10nowhere");
    }

    public static native int nwShared(int x);
}

class NwMissing {
    static {
        System.loadLibrary("a10nowhere");
    }

    public static native int nwShared(int x);
}

class NwRtA {
    static {
        System.loadLibrary("a10nowhere");
    }

    public static native long nwRt(long t);
}

class NwRtB {
    static {
        System.loadLibrary("a10nowhere");
    }

    public static native long nwRt(long t);
}

class NwElsewhere {
    static {
        System.loadLibrary("a10nowhere");
    }

    public static native int nwShared(int x);

    public static native long nwMine(long t);
}
