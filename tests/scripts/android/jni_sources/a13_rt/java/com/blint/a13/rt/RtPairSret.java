package com.blint.a13.rt;

/**
 * A13 U1 - the pair-passing chain whose callee makes its own sret call
 * before reading the incoming pair. rtOne and rtShared bind through
 * runtime_table on the 32-bit ABIs and stay unbound everywhere else.
 */
public class RtPairSret {
    public static native int rtOne(int x);

    public static native long rtShared(long t);
}
