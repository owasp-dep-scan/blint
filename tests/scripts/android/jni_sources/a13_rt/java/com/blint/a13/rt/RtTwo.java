package com.blint.a13.rt;

/**
 * The refusal twin. The registrar's cold init path names two
 * classes, so the RegisterNatives call that no class materialization
 * precedes stays unread and rtOne stays unbound on every ABI.
 */
public class RtTwo {
    public static native int rtOne(int x);
}
