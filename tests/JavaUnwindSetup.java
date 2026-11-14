/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import one.profiler.AsyncProfiler;

public final class JavaUnwindSetup {
    private static volatile long sink;

    static long work(int count) {
        long value = 0;
        for (int i = 0; i < count; i++) value += (i * 31L) ^ (value >>> 3);
        return value;
    }

    static long middle(int count) { return work(count) + 1; }

    static int thrower(int value) {
        if ((value & 7) == 0) throw new IllegalStateException();
        return value;
    }

    static int catcher(int value) {
        try { return thrower(value); }
        catch (IllegalStateException ignored) { return -1; }
    }

    private static void warm() {
        sink += middle(200_000);
        for (int i = 0; i < 2_000; i++) sink += catcher(i);
    }

    public static void main(String[] args) throws Exception {
        var profiler = AsyncProfiler.getInstance(Path.of(args[0]).toAbsolutePath().toString());
        long until = System.nanoTime() + Long.parseLong(args[1]) * 1_000_000_000L;
        for (int i = 0; i < 200 || System.nanoTime() < until; i++) warm();
        if (args[2].equals("cpu")) {
            profiler.execute("start,event=cpu,interval=1ms,cstack=vm");
            long end = System.nanoTime() + 3_000_000_000L;
            while (System.nanoTime() < end) sink += middle(200_000);
            profiler.stop();
            long total = 0, rooted = 0;
            for (var line : profiler.execute("collapsed").split("\n")) {
                if (!line.contains("JavaUnwindSetup.work")) continue;
                long samples = Long.parseLong(line.substring(line.lastIndexOf(' ') + 1));
                total += samples;
                if (line.contains("JavaUnwindSetup.main;JavaUnwindSetup.middle;JavaUnwindSetup.work")) rooted += samples;
            }
            System.out.println("WORK_SAMPLES total=" + total + " rooted=" + rooted);
        }
        // Provider capture prepares Java metadata and unwind tables before it
        // opens an ETW session, so an ordinary-privilege target still prepares them.
        try {
            profiler.execute("start,event=trace:{2a94e71b-655a-4f69-8c64-302d17032ae9}/1,file=" + args[3]);
            profiler.stop();
            System.out.println("PREPARE started");
        } catch (Exception e) {
            System.out.println("PREPARE_ERROR " + e.getMessage());
        }
        for (var line : profiler.execute("metrics").split("\n")) {
            if (line.startsWith("windows_java")) System.out.println(line);
        }
    }
}
