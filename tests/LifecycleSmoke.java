/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Files;
import java.nio.file.Path;
import one.profiler.AsyncProfiler;

public final class LifecycleSmoke {
    static volatile long result;

    static void burn() {
        var value = result;
        for (var i = 0; i < 100_000; i++) value = Long.rotateLeft(value ^ i, 13) * 0x100000001b3L;
        result = value;
    }

    static int awaitTimeout(AsyncProfiler profiler, int seconds) throws Exception {
        var started = System.nanoTime();
        var nextCheck = started;
        var previousSamples = profiler.getSamples();
        var resets = 0;
        while (System.nanoTime() - started < (seconds + 15L) * 1_000_000_000L) {
            burn();
            if (System.nanoTime() >= nextCheck) {
                var samples = profiler.getSamples();
                if (samples < previousSamples) resets++;
                previousSamples = samples;
                if (profiler.execute("status").contains("not active")) {
                    var elapsed = (System.nanoTime() - started) / 1_000_000;
                    if (elapsed < seconds * 800L) {
                        throw new AssertionError("Unexpected timeout duration: " + elapsed);
                    }
                    System.out.println("AUTOMATIC_STOP_OK elapsedMs=" + elapsed + " resets=" + resets);
                    return resets;
                }
                nextCheck = System.nanoTime() + 50_000_000L;
            }
        }
        throw new AssertionError("Profiler did not stop automatically");
    }

    static long start(AsyncProfiler profiler, Path file, String options) throws Exception {
        profiler.execute("start,event=cpu,interval=1ms,cstack=no," + options + ",file=" + file);
        return System.currentTimeMillis();
    }

    static void limit(Path file, long started, int seconds) {
        System.out.println("CAPTURE_LIMIT " + (started + seconds * 1000L) + " " + file);
    }

    static void totals(AsyncProfiler profiler, Path file) throws Exception {
        Files.writeString(Path.of(file + ".collapsed"), profiler.execute("collapsed,total"));
    }

    public static void main(String[] args) throws Exception {
        var profiler = AsyncProfiler.getInstance(Path.of(args[0]).toAbsolutePath().toString());
        var directory = Path.of(args[1]);
        var pid = ProcessHandle.current().pid();
        var jfr = "jfr" + (args.length > 2 ? ",jfrsync=profile" : "");
        for (var i = 0; i < 1000; i++) burn();
        var longOutput = directory.resolve(System.getenv("ASPROF_LONG_FILENAME") + ".jfr");
        Files.createFile(longOutput);
        Files.delete(longOutput);
        var started = start(profiler, directory.resolve("%{ASPROF_LONG_FILENAME}.jfr"), "timeout=1," + jfr);
        limit(longOutput, started, 1);
        awaitTimeout(profiler, 1);
        if (!Files.isRegularFile(longOutput)) throw new AssertionError("Long expanded filename was lost");
        totals(profiler, longOutput);
        System.out.println("LONG_TEMPLATE_OK utf8Bytes=" + longOutput.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
        var pattern = directory.resolve("timeout-%p-%t-%{ASPROF_FILENAME}.jfr");
        started = start(profiler, pattern, "timeout=1," + jfr);
        awaitTimeout(profiler, 1);
        try (var paths = Files.list(directory)) {
            var files = paths.toList();
            var matches = files.stream().filter(path -> path.getFileName().toString().matches("timeout-" + pid
                    + "-[0-9]{8}-[0-9]{6}-" + System.getenv("ASPROF_FILENAME") + "\\.jfr")).toList();
            if (matches.size() != 1) throw new AssertionError("Target PID/time/environment expansion failed: " + files);
            limit(matches.get(0), started, 1);
            totals(profiler, matches.get(0));
        }
        started = start(profiler, directory.resolve("loop-%n{2}.jfr"), "timeout=4,loop=1," + jfr);
        if (awaitTimeout(profiler, 4) < 2) throw new AssertionError("JFR loop did not reset through a complete two-file ring");
        for (var i = 0; i < 2; i++) {
            if (!Files.isRegularFile(directory.resolve("loop-" + i + ".jfr"))) throw new AssertionError("Missing loop output " + i);
            limit(directory.resolve("loop-" + i + ".jfr"), started, 4);
        }
        var chunks = directory.resolve("chunks-" + pid + ".jfr");
        started = start(profiler, chunks, "timeout=11,chunktime=5," + jfr);
        limit(chunks, started, 11);
        awaitTimeout(profiler, 11);
        totals(profiler, chunks);
        start(profiler, directory.resolve("folded-%n{2}.collapsed"), "timeout=3,loop=1,collapsed");
        if (awaitTimeout(profiler, 3) < 2) throw new AssertionError("Collapsed loop did not reset through a complete two-file ring");
        System.out.println("NATIVE_LIFECYCLE_OK");
    }
}
