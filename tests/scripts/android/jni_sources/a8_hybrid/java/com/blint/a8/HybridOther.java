package com.blint.a8;

public class HybridOther {
    public native int hybPair(int a, int b);

    /** Same name as HybridFirst.hybTick but a different signature. */
    public native long hybTick(long when);
}
