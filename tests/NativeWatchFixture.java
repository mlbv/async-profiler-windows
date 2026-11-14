/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.io.BufferedReader;
import java.io.InputStreamReader;

public final class NativeWatchFixture {
    private static native long address();
    private static native long function();
    private static native long run();
    public static void main(String[] args) throws Exception {
        System.load(args[0]);
        var input = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("READY " + ProcessHandle.current().pid());
        for (var command = input.readLine(); command != null && !command.equals("quit"); command = input.readLine()) {
            if (command.equals("address")) System.out.println("ADDRESS " + Long.toUnsignedString(address(), 16));
            else if (command.equals("function")) System.out.println("ADDRESS " + Long.toUnsignedString(function(), 16));
            else System.out.println("RESULT " + run());
        }
    }
}
