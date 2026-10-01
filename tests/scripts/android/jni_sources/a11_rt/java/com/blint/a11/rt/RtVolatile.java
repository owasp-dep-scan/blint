package com.blint.a11.rt;

/**
 * The volatile-count registrar's declaring class (see RtNative): its rows
 * must stay unrecovered - the count is a run-time value, so no entry count
 * can be read beside the methods pointer.
 */
public class RtVolatile {
    public static native int rtOne(int x);

    public static native long rtShared(long t);
}
