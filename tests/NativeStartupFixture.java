/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
public final class NativeStartupFixture {
    private static native long run();
    public static void main(String[] args) {
        System.load(args[0]);
        if (run() != ProcessHandle.current().pid() * 100) throw new AssertionError("Native call result changed");
        System.out.println("STARTUP_OK");
    }
}
