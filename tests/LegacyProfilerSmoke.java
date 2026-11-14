/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import one.profiler.AsyncProfiler;
import one.profiler.Recording;
import one.profiler.Span;

public final class LegacyProfilerSmoke {
    static volatile long result;

    static void 燃烧𠮷() {
        long value = result;
        for (int i = 0; i < 100_000; i++) value = Long.rotateLeft(value ^ i, 13) * 0x100000001b3L;
        result = value;
    }

    static void outer() { 燃烧𠮷(); }
    static void work(long millis) {
        long end = System.nanoTime() + millis * 1_000_000L;
        while (System.nanoTime() < end) outer();
    }

    public static void main(String[] args) throws Exception {
        boolean preloaded = args.length > 3;
        if (!preloaded && (Recording.state() != Recording.UNAVAILABLE || Span.start() != 0)) throw new AssertionError("Unexpected initial SDK state");
        AsyncProfiler profiler = AsyncProfiler.getInstance(args[0]);
        if (!profiler.getVersion().contains("4.5-windows")) throw new AssertionError("Unexpected native profiler version");
        work(600);
        String event = args[2];
        String features = System.getProperty("asprof.test.features", "");
        String cstack = features.contains("agct") ? "no" : "vm";
        if (!preloaded) profiler.execute("start,event=" + event + ",interval=" + (event.equals("cycles") ? "1000000" : event.startsWith("etw:") ? "1ms" : "10ms")
                + ",cstack=" + cstack + (features.isEmpty() ? "" : ",features=" + features) + ",jfr,file=" + args[1]);
        if (Recording.state() != Recording.RUNNING) throw new AssertionError("SDK did not observe capture start");
        long span = Span.start();
        try { work(2000); }
        finally { Span.end(span, "legacy." + event + ".\ud83d\ude42"); profiler.stop(); }
        if (Recording.state() != Recording.STOPPED || profiler.getSamples() == 0) throw new AssertionError("Capture or SDK stop failed");
        Files.write(Paths.get(args[1] + ".collapsed"), profiler.execute("collapsed,total").getBytes(StandardCharsets.UTF_8));
        System.out.println(profiler.execute("metrics"));
        System.out.println("LEGACY_PROFILER_OK " + System.getProperty("java.version"));
    }
}
