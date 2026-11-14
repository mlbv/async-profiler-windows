/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import one.profiler.AsyncProfiler;

public final class RawPmuGrammar {
    public static void main(String[] args) throws Exception {
        var profiler = AsyncProfiler.getInstance(Path.of(args[0]).toAbsolutePath().toString());
        var range = args.length > 1 && args[1].equals("range");
        try {
            profiler.execute(range ? "start,event=rc0,interval=1000" : "start,event=cpu/event=0xc0,umask=0/,interval=1000000");
            try { profiler.stop(); } finally { throw new AssertionError("Invalid raw PMU request unexpectedly reached capture"); }
        } catch (IllegalArgumentException | IllegalStateException expected) {
            // Arguments separates top-level options at commas before the PMU
            // parser runs. Colon separators keep the descriptor in one option.
            if (range ? !expected.getMessage().contains("outside this Windows source's supported range")
                    : !expected.getMessage().contains("end with '/'") && !expected.getMessage().contains("Unknown argument")) throw expected;
            System.out.println((range ? "RAW_PMU_RANGE_REJECTED " : "RAW_PMU_COMMA_REJECTED ") + expected.getMessage());
        }
        if (!profiler.execute("status").contains("not active")) throw new AssertionError("Failed descriptor started profiling");
        if (profiler.execute("list").contains("asprof-raw-")) throw new AssertionError("Failed descriptor registered a source");
    }
}
