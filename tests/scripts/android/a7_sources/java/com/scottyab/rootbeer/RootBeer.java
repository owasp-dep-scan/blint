/*
 * The caller that moves the su paths from dex to native.
 *
 * Cut down from scottyab/rootbeer (Apache-2.0) rootbeerlib
 * src/main/java/com/scottyab/rootbeer/RootBeer.java at 0.1.2:
 * checkForBinary/checkForRootNative are the two halves the fixture needs —
 * the directory list plus the "su" slug build the paths in Java, and the
 * native checkForRoot receives them as a String[] (which is why the native
 * library holds no constant su path).
 */
package com.scottyab.rootbeer;

public class RootBeer {

    private static final String BINARY_SU = "su";

    public boolean checkForSuBinary() {
        return checkForBinary(BINARY_SU);
    }

    private boolean checkForBinary(String slug) {
        String[] paths = Const.getPaths();
        String[] candidates = new String[paths.length];
        for (int i = 0; i < paths.length; i++) {
            candidates[i] = paths[i] + slug;
        }
        return checkForRootNative(candidates);
    }

    private boolean checkForRootNative(String[] paths) {
        RootBeerNative nativeChecker = new RootBeerNative();
        if (!nativeChecker.wasNativeLibraryLoaded()) {
            return false;
        }
        return nativeChecker.checkForRoot(paths) > 0;
    }
}
