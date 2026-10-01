package com.blint.a11.rt;

/**
 * A11 S3 - the runtime-table fixture's declarations.
 *
 * <ul>
 *   <li>rtStaticAdd - static-table control; must bind on every ABI.</li>
 *   <li>rtOne, declared by RtNative and RtVolatile - registered by the two
 *   runtime-built tables: RtNative's registrar passes a constant count (the
 *   shape the walk can read), RtVolatile's passes the volatile count (the
 *   adjacent shape that must stay unrecovered wherever the count is not a
 *   constant). Both tables are built at run time, so without the walk no
 *   static triple exists for either.</li>
 *   <li>rtShared, declared by RtNative and RtVolatile - the two tables'
 *   second entries point at different implementations (a and b); only the
 *   constant-count registration can carry an fn_addr.</li>
 * </ul>
 */
public class RtNative {
    static {
        System.loadLibrary("a11rt");
    }

    public static native int rtStaticAdd(int x);

    public static native int rtOne(int x);

    public static native long rtShared(long t);
}
