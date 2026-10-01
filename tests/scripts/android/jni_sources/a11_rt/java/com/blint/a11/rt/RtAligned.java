package com.blint.a11.rt;

/**
 * The alignment registrar's declaring class: same runtime-built single
 * entry as RtNative's rtOne, staged into a 16-aligned buffer (the 32-bit
 * prologue realigns esp first). The walk must still read it.
 */
public class RtAligned {
    public static native int rtOne(int x);
}
