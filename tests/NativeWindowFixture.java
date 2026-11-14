/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.io.BufferedReader;
import java.io.InputStreamReader;

public final class NativeWindowFixture {
    private static native long run(int mode);

    public static void main(String[] args) throws Exception {
        System.load(args[0]);
        var input = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("READY " + ProcessHandle.current().pid());
        for (var command = input.readLine(); command != null && !command.equals("quit"); command = input.readLine()) {
            var mode = command.equals("cpu") ? 1 : command.equals("private") ? 2 : command.equals("parallel") ? 3 : 0;
            System.out.println("RESULT " + run(mode));
        }
    }
}
