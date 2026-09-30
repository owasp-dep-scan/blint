package com.blint.a10.gap;

/**
 * A10 Q1 - the five declarations of the 32-bit-gap fixture, one per shape.
 *
 * <ul>
 *   <li>plainAdd - control; must bind on every ABI.</li>
 *   <li>weakOnly - the signature word relocates against a weak preemptible
 *   OBJECT dynsym (fbjni's kDescriptor shape); must bind on every ABI,
 *   including the REL ones.</li>
 *   <li>nounwindAdd - the implementation is a real function compiled without
 *   unwind tables and hidden: its triple's words all relocate, and it must
 *   stay unbound on every ABI because no start source can verify the
 *   fnPtr (the RnHello v7a yoga wrappers' shape).</li>
 *   <li>smallOnly - the registrar builds the entry at run time through a
 *   noinline constructor; no static triple exists, so it must stay unbound
 *   on every ABI.</li>
 *   <li>decoyDataFn - the fnPtr word relocates against a defined OBJECT,
 *   not a function; must stay unbound.</li>
 * </ul>
 */
public class GapNative {
    static {
        System.loadLibrary("a10gap");
    }

    public static native int plainAdd(int x);

    public static native int weakOnly(int x);

    public static native int nounwindAdd(int x);

    public static native int smallOnly(int x);

    public static native int decoyDataFn(int x);
}
