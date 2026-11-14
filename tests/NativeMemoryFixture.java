/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;

public final class NativeMemoryFixture {
    private static native long[] run();
    private static native int stress(int count);
    private static native long[] aligned();
    private static native long[] debug();
    private static native long[] expand();
    private static native long[] base();
    private static native long[] provider(String path, int phase);
    private static native int cpuCreate();
    private static native long[] cpuRun(boolean kernel, int duration);
    private static native void cpuClose();

    public static void main(String[] args) throws Exception {
        if (args.length > 1 && args[1].equals("early")) System.load(args[0]);
        var input = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("READY " + ProcessHandle.current().pid());
        for (var command = input.readLine(); command != null && !command.equals("quit"); command = input.readLine()) {
            if (command.equals("load")) {
                System.load(args[0]);
                System.out.println("LOADED");
            } else if (command.equals("stress")) {
                System.out.println("STRESSED " + stress(30000));
            } else if (command.equals("aligned")) {
                System.out.println("POINTERS " + Arrays.toString(aligned()));
            } else if (command.equals("debug")) {
                System.out.println("POINTERS " + Arrays.toString(debug()));
            } else if (command.equals("expand")) {
                System.out.println("POINTERS " + Arrays.toString(expand()));
            } else if (command.equals("base")) {
                System.out.println("POINTERS " + Arrays.toString(base()));
            } else if (command.startsWith("provider ")) {
                var request = command.substring(9);
                var separator = request.indexOf(' ');
                System.out.println("POINTERS " + Arrays.toString(provider(request.substring(separator + 1), Integer.parseInt(request.substring(0, separator)))));
            } else if (command.equals("cpu-create")) {
                System.out.println("CPU_TID " + cpuCreate());
            } else if (command.startsWith("cpu-run ")) {
                var request = command.split(" ");
                System.out.println("CPU_TIMES " + Arrays.toString(cpuRun(request[1].equals("kernel"), Integer.parseInt(request[2]))));
            } else if (command.equals("cpu-close")) {
                cpuClose();
                System.out.println("CPU_CLOSED");
            } else {
                System.out.println("POINTERS " + Arrays.toString(run()));
            }
        }
    }
}
