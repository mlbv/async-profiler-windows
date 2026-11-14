/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.management.ManagementFactory;

public final class NativeLatencyFixture {
    static int work(int value) throws InterruptedException {
        if ((value & 1) != 0) Thread.sleep(15);
        return value * 3;
    }
    static int second(int value) { return value + 1; }
    public static void main(String[] args) throws Exception {
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("READY " + ManagementFactory.getRuntimeMXBean().getName());
        for (String command = input.readLine(); command != null && !command.equals("quit"); command = input.readLine()) {
            boolean both = command.startsWith("both ");
            int count = Integer.parseInt(both ? command.substring(5) : command);
            int sum = 0;
            for (int i = 0; i < count; i++) {
                sum += work(i);
                if (both) sum += second(i);
            }
            System.out.println("DONE " + count + " " + sum);
        }
    }
}
