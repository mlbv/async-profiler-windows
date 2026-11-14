/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
// The workload of upstream's test.nonjava.JavaClass.
public class NonjavaTask {
    public static double cpuHeavyTask() {
        double sum = 0;
        for (int i = 0; i < 100000; i++) {
            sum += Math.sqrt(Math.random());
            sum += Math.pow(Math.random(), Math.random());
        }
        return sum;
    }
}
