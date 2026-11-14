/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;

public final class NativeOsLockFixture {
    private static native long[] run();
    public static void main(String[] args) throws Exception {
        System.load(args[0]);
        var input = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("READY " + ProcessHandle.current().pid());
        for (var command = input.readLine(); command != null && !command.equals("quit"); command = input.readLine()) {
            System.out.println("LOCKS " + Arrays.toString(run()));
        }
    }
}
