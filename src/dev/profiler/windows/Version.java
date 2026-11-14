/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
package dev.profiler.windows;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/** The build identity printed by the launchers' -v; Java 8 compatible for jfrconv. */
public final class Version {
    private Version() {}

    static String line(String product) throws IOException {
        Properties build = new Properties();
        try (InputStream input = Version.class.getResourceAsStream("version.properties")) {
            build.load(input);
        }
        return product + " " + build.getProperty("version") + " built on " + build.getProperty("date");
    }

    public static void main(String[] args) throws IOException {
        System.out.println(line(args[0]));
    }
}
