/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Files;
import java.nio.file.Path;
import one.profiler.AsyncProfiler;

public final class NativeProbePeriod {
    private static native long calls(int count, long first);
    private static native long uneven();
    private static native long windows();

    static void start(AsyncProfiler profiler, Path output, String options) throws Exception {
        profiler.execute("start,event=nativeProbePeriod.dll!ProbeArgumentsWork{1},interval=5,cstack=vm,jfr,file=" + output + options);
    }

    static void finish(AsyncProfiler profiler, Path output, long hits, long samples) throws Exception {
        profiler.stop();
        Files.writeString(Path.of(output + ".collapsed"), profiler.execute("collapsed,total"));
        var metrics = profiler.execute("metrics");
        if (!metrics.contains("windows_probe_calls " + hits + "\n") || !metrics.contains("windows_probe_samples " + samples + "\n")
                || !metrics.contains("windows_probe_failed 0\n") || !metrics.contains("windows_probe_dropped 0\n")
                || !metrics.contains("windows_breakpoint_targets 0\n")) throw new AssertionError("Probe period or cleanup counters changed: " + metrics);
        System.out.println(output.getFileName() + " enabledHits=" + hits + " samples=" + samples + " cleanup=0");
    }

    public static void main(String[] args) throws Exception {
        var profiler = AsyncProfiler.getInstance(Path.of(args[0]).toAbsolutePath().toString());
        System.load(Path.of(args[1]).toAbsolutePath().toString());
        var directory = Path.of(args[2]);
        var output = directory.resolve("uneven.jfr");
        start(profiler, output, "");
        try { if (uneven() != 185834) throw new AssertionError("Native worker results changed"); }
        finally { finish(profiler, output, 10, 1); }

        output = directory.resolve("window-phase.jfr");
        start(profiler, output, ",begin=nativeProbePeriod.dll!WindowBegin,end=nativeProbePeriod.dll!WindowEnd");
        try { if (windows() != 186718) throw new AssertionError("Native window results changed"); }
        finally { finish(profiler, output, 6, 2); }

        output = directory.resolve("filter-phase.jfr");
        start(profiler, output, ",filter");
        try {
            calls(2,101);
            profiler.addThread(Thread.currentThread());
            calls(3,201);
            profiler.removeThread(Thread.currentThread());
            calls(2,301);
            profiler.addThread(Thread.currentThread());
            calls(3,401);
        } finally { finish(profiler, output, 6, 2); }

        output = directory.resolve("epoch-before.jfr");
        start(profiler, output, "");
        try { calls(3,501); }
        finally { finish(profiler, output, 3, 0); }
        output = directory.resolve("epoch-after.jfr");
        start(profiler, output, "");
        try { calls(2,601); calls(3,603); }
        finally { finish(profiler, output, 5, 1); }
    }
}
