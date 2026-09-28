/*
 * A7 K1 — the dex half of the RootBeer JNI-join fixture.
 *
 * Verbatim from scottyab/rootbeer (Apache-2.0) rootbeerlib
 * src/main/java/com/scottyab/rootbeer/RootBeerNative.java at tag 0.1.2
 * (QLog replaced with System.err so the class stands alone in the fixture
 * build). The original package is kept deliberately: libtoolChecker.so is
 * the unmodified 0.1.2 native side, and the join's bound side needs the
 * original Java_com_scottyab_rootbeer_RootBeerNative_* names to resolve.
 */
package com.scottyab.rootbeer;

public class RootBeerNative {

    private static boolean libraryLoaded = false;

    /**
     * Loads the C/C++ libraries statically
     */
    static {
        try {
            System.loadLibrary("toolChecker");
            libraryLoaded = true;
        } catch (UnsatisfiedLinkError e) {
            System.err.println("toolChecker load failed: " + e);
        }
    }

    public boolean wasNativeLibraryLoaded() {
        return libraryLoaded;
    }

    public native int checkForRoot(Object[] pathArray);

    public native int setLogDebugMessages(boolean logDebugMessages);

}
