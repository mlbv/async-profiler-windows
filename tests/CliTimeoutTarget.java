/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.io.BufferedReader;
import java.io.InputStreamReader;
import one.profiler.AsyncProfiler;

/** Runs bounded CPU work between blocking controller commands. */
public final class CliTimeoutTarget {
    private static volatile long result;

    static void burn() {
        var value = result;
        for (var i = 0; i < 100_000; ++i) value = Long.rotateLeft(value ^ i, 13) * 0x100000001b3L;
        result = value;
    }

    public static void main(String[] args) throws Exception {
        var profiler = AsyncProfiler.getInstance(args[0]);
        if (args.length > 1) {
            var end = System.nanoTime() + Long.parseLong(args[1]) * 1_000_000L;
            while (System.nanoTime() < end) burn();
            return;
        }
        var input = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("READY " + ProcessHandle.current().pid());
        for (var line = input.readLine(); line != null && !line.equals("quit"); line = input.readLine()) {
            var fields = line.split(" ");
            var end = System.nanoTime() + Long.parseLong(fields[0]) * 1_000_000L;
            while (System.nanoTime() < end) burn();
            var active = profiler.execute("status").contains("is running");
            if (active != Boolean.parseBoolean(fields[1])) throw new AssertionError("Unexpected profiler state: " + active);
            System.out.println("WORK_DONE " + fields[0] + " active=" + active);
        }
    }
}
