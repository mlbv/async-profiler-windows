/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.io.BufferedReader;
import java.io.InputStreamReader;

public final class NativeApiFixture {
    private static native String run();
    private static native byte[] output();
    public static void main(String[] args) throws Exception {
        System.load(args[0]);
        var input = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("READY " + ProcessHandle.current().pid());
        for (var command = input.readLine(); command != null && !command.equals("quit"); command = input.readLine()) {
            var result = run();
            java.nio.file.Files.write(java.nio.file.Path.of(args[1]), output());
            System.out.println(result);
        }
    }
}
