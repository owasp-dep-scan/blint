/*
 * The fixture driver: exercises the RootBeer half and one benign
 * native-adjacent read (an SDK probe string in the same dex, which must
 * not turn into a finding on its own).
 */
package com.example.blint.a7;

import com.scottyab.rootbeer.RootBeer;

public class Main {

    public static void main(String[] args) {
        RootBeer rootBeer = new RootBeer();
        boolean rooted = rootBeer.checkForSuBinary();
        String sdkProp = "ro.build.version.sdk";
        System.out.println("rooted=" + rooted + " sdk=" + sdkProp);
    }
}
