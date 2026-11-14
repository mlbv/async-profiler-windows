/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
/** Starts the given command as a child process, as a Java application under asprof-helper --preload would. */
public final class PreloadChildLauncher {
    public static void main(String[] args) throws Exception {
        var child = new ProcessBuilder(args).inheritIO().start();
        System.out.println("CHILD " + child.pid());
        System.out.flush();
        System.exit(child.waitFor());
    }
}
