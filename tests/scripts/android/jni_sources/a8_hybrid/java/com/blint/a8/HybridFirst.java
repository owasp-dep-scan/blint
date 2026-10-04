package com.blint.a8;

/** The fbjni-shape declarations: bound dynamically once the merged
 *  tables recover (the join's bound_dynamic). */
public class HybridFirst {
    public static native HybridFirst hybInit();

    public native void hybTick(long when);

    public native String hybName(String s);

    /** No table anywhere answers this one: the unbound residue. */
    public native String hybMissing(String s);
}
