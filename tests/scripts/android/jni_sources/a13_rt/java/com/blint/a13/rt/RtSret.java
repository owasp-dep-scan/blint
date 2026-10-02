package com.blint.a13.rt;

/**
 * A13 U1 - the sret declaration. The registrar stores the entry words
 * before the class finder returns through a caller-frame pointer the
 * callee pops, and computes the methods pointer after the caller's
 * re-alignment; rtOne binds through runtime_table on the 32-bit ABIs and
 * stays unbound everywhere else.
 */
public class RtSret {
    public static native int rtOne(int x);
}
