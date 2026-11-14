/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */
package test.api;

import java.util.HashSet;
import one.profiler.AsyncProfiler;

public class MetricsTest {

    static void doStuff() {}

    public static void main(String[] args) throws Exception {
        AsyncProfiler profiler = AsyncProfiler.getInstance();
        String nullDevice = System.getProperty("os.name").startsWith("Windows") ? "NUL" : "/dev/null";
        profiler.execute("start,trace=test.api.MetricsTest.doStuff,features=stats,jfr,file=" + nullDevice);

        doStuff();
        doStuff();
        doStuff();

        String metrics = profiler.execute("metrics");
        for (String line : metrics.split("\n")) {
            String[] pair = line.split(" ");
            assert pair.length == 2 : line;
            // The Windows build adds events_dropped_total and windows_* diagnostics, which this run leaves at zero
            if (pair[1].startsWith("0") && !pair[0].equals("events_dropped_total") && !pair[0].startsWith("windows_")) {
                assert "samples_skipped_total".equals(pair[0]) || "calltracestorage_overflows_total".equals(pair[0]) : line;
            }

            if (pair[0].equals("samples_total")) {
                assert pair[1].equals("3") : line;
            }
        }

        // Should be found since we used features=stats
        assert metrics.contains("stackwalk_ns_total") : metrics;
    }
}
