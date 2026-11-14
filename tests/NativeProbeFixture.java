/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.io.BufferedReader;
import java.io.InputStreamReader;

public final class NativeProbeFixture {
    private static native long run();
    private static native void background(boolean start);
    private static native void churn();

    public static void main(String[] args) throws Exception {
        System.load(args[0]);
        var input = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("READY " + ProcessHandle.current().pid());
        for (var command = input.readLine(); command != null && !command.equals("quit"); command = input.readLine()) {
            switch (command) {
                case "background" -> { background(true); System.out.println("BACKGROUND"); }
                case "finish" -> { background(false); System.out.println("FINISHED"); }
                case "churn" -> { churn(); System.out.println("CHURNED"); }
                default -> System.out.println("RESULT " + run());
            }
        }
    }
}
