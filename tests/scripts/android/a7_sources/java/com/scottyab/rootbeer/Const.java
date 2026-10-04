/*
 * The su-path list, from the same source tree and tag as the
 * native side: scottyab/rootbeer (Apache-2.0) rootbeerlib
 * src/main/java/com/scottyab/rootbeer/Const.java at 0.1.2, suPaths and
 * getPaths() only.
 */
package com.scottyab.rootbeer;

import java.util.ArrayList;
import java.util.Arrays;

final class Const {

    private static final String[] suPaths = {
            "/data/local/",
            "/data/local/bin/",
            "/data/local/xbin/",
            "/sbin/",
            "/su/bin/",
            "/system/bin/",
            "/system/bin/.ext/",
            "/system/bin/failsafe/",
            "/system/sd/xbin/",
            "/system/usr/we-need-root/",
            "/system/xbin/",
            "/system_ext/bin/",
            "/cache/",
            "/data/",
            "/dev/"
    };

    private Const() {
    }

    static String[] getPaths() {
        ArrayList<String> paths = new ArrayList<>(Arrays.asList(suPaths));
        return paths.toArray(new String[0]);
    }
}
