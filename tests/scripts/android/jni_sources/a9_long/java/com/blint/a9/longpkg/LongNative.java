package com.blint.a9.longpkg;

/**
 * A9 P2 - the string-bound fixtures for the RegisterNatives recovery.
 *
 * sigUnder: 17 GrandParent.Parent.Child parameters, a 954-byte descriptor
 *           - over the recovery's old 256-byte read, under
 *           JNI_STRING_READ_LIMIT (1024): the table entry must recover and
 *           the declaration must bind.
 * sigLong:  22 parameters, a 1234-byte descriptor - past
 *           JNI_STRING_READ_LIMIT: the entry must stay refused and the
 *           declaration unbound.
 * nameLong: a 1120-char method name - past the same limit: must stay
 *           refused rather than bind as its truncated prefix.
 *
 * The strings are repetitions of one descriptor segment, so the lengths
 * above are reproducible by counting the parameters.
 */
public class LongNative {
    static {
        System.loadLibrary("a9long");
    }

    public static class GrandParent {
        public static class Parent {
            public static class Child {}
        }
    }

    public static native void sigUnder(GrandParent.Parent.Child p00, GrandParent.Parent.Child p01, GrandParent.Parent.Child p02, GrandParent.Parent.Child p03, GrandParent.Parent.Child p04, GrandParent.Parent.Child p05, GrandParent.Parent.Child p06, GrandParent.Parent.Child p07, GrandParent.Parent.Child p08, GrandParent.Parent.Child p09, GrandParent.Parent.Child p10, GrandParent.Parent.Child p11, GrandParent.Parent.Child p12, GrandParent.Parent.Child p13, GrandParent.Parent.Child p14, GrandParent.Parent.Child p15, GrandParent.Parent.Child p16);

    public static native void sigLong(GrandParent.Parent.Child q00, GrandParent.Parent.Child q01, GrandParent.Parent.Child q02, GrandParent.Parent.Child q03, GrandParent.Parent.Child q04, GrandParent.Parent.Child q05, GrandParent.Parent.Child q06, GrandParent.Parent.Child q07, GrandParent.Parent.Child q08, GrandParent.Parent.Child q09, GrandParent.Parent.Child q10, GrandParent.Parent.Child q11, GrandParent.Parent.Child q12, GrandParent.Parent.Child q13, GrandParent.Parent.Child q14, GrandParent.Parent.Child q15, GrandParent.Parent.Child q16, GrandParent.Parent.Child q17, GrandParent.Parent.Child q18, GrandParent.Parent.Child q19, GrandParent.Parent.Child q20, GrandParent.Parent.Child q21);

    public static native int a9LongNameXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyzXyz(int x);
}
