/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.management.ManagementFactory;

public final class NativeMethodFixture {
    static volatile int sink;

    static int work(int value) {
        try {
            switch (value % 4) {
                case 0: return value * 2;
                case 1: return value + 3;
                case 2: return Integer.parseInt("7") + value;
                default: throw new IllegalArgumentException();
            }
        } catch (IllegalArgumentException e) {
            return -value;
        } finally {
            sink = value;
        }
    }

    public static void main(String[] args) throws Exception {
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("READY " + ManagementFactory.getRuntimeMXBean().getName());
        for (String command = input.readLine(); command != null && !command.equals("quit"); command = input.readLine()) {
            int count = Integer.parseInt(command);
            long sum = 0L;
            for (int i = 0; i < count; i++) sum += work(i);
            System.out.println("DONE " + count + " " + sum);
        }
    }
}
