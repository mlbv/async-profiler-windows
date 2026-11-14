/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.io.BufferedReader;
import java.io.InputStreamReader;

public final class NativeProbeArguments {
    private static native long address(boolean function);
    private static native long run(boolean memory);

    public static void main(String[] args) throws Exception {
        System.load(args[0]);
        var input = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("READY " + ProcessHandle.current().pid());
        for (var command = input.readLine(); command != null && !command.equals("quit"); command = input.readLine()) {
            switch (command) {
                case "address" -> System.out.println("ADDRESS " + Long.toUnsignedString(address(false)));
                case "function" -> System.out.println("ADDRESS " + Long.toUnsignedString(address(true)));
                default -> System.out.println("RESULT " + run(command.equals("watch")));
            }
        }
    }
}
