/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;
import jdk.jfr.consumer.RecordingFile;
import one.profiler.AsyncProfiler;

public final class SignalRoutingSmoke {
    static volatile long result;

    static void leaf() {
        var value = result;
        for (var i = 0; i < 100_000; i++) value = Long.rotateLeft(value + i, 9);
        result = value;
    }

    static void outer() { leaf(); }

    static void reject(AsyncProfiler profiler, String options, String expected) throws Exception {
        try {
            profiler.execute("start," + options);
        } catch (IllegalArgumentException | IllegalStateException error) {
            if (!error.getMessage().contains(expected)) throw error;
            System.out.println("Rejected " + options + ": " + error.getMessage());
            return;
        }
        profiler.stop();
        throw new AssertionError("Accepted invalid options: " + options);
    }

    static void capture(AsyncProfiler profiler, Path output, String event, String signals) throws Exception {
        profiler.execute("start,event=" + event + ",interval=" + (event.equals("cycles") ? "1000000" : "1ms")
                + ",wall=5ms,cstack=no,signal=" + signals + ",jfr,file=" + output);
        try {
            var deadline = System.nanoTime() + 1_500_000_000L;
            while (System.nanoTime() < deadline) outer();
        } finally {
            profiler.stop();
        }
        var cpu = 0;
        var wall = 0;
        var sleeping = 0;
        for (var sample : RecordingFile.readAllEvents(output)) {
            var type = sample.getEventType().getName();
            if (!type.equals("jdk.ExecutionSample") && !type.equals("profiler.WallClockSample")) continue;
            var thread = sample.getThread("sampledThread");
            if (type.equals("profiler.WallClockSample") && thread != null
                    && ("signal-sleeper".equals(thread.getJavaName()) || "signal-sleeper".equals(thread.getOSName()))) sleeping++;
            if (sample.getStackTrace() == null) continue;
            var leaf = false;
            var outer = false;
            for (var frame : sample.getStackTrace().getFrames()) {
                var method = frame.getMethod();
                if (!method.getType().getName().equals("SignalRoutingSmoke")) continue;
                leaf |= method.getName().equals("leaf");
                outer |= method.getName().equals("outer");
            }
            if (leaf && outer) {
                if (type.equals("jdk.ExecutionSample")) cpu++;
                else wall++;
            }
        }
        if (cpu < 10 || wall < 10 || sleeping == 0) {
            throw new AssertionError("Signal routing lost stacks: cpu=" + cpu + " wall=" + wall + " sleeping=" + sleeping);
        }
        System.out.println(event + " signal=" + signals + " cpu=" + cpu + " wall=" + wall + " sleeping=" + sleeping);
    }

    public static void main(String[] args) throws Exception {
        var profiler = AsyncProfiler.getInstance(Path.of(args[0]).toAbsolutePath().toString());
        var directory = Path.of(args[1]);
        var running = new AtomicBoolean(true);
        var sleeper = new Thread(() -> {
            while (running.get()) {
                try { Thread.sleep(20); }
                catch (InterruptedException ignored) { return; }
            }
        }, "signal-sleeper");
        sleeper.start();
        try {
            var deadline = System.nanoTime() + 500_000_000L;
            while (System.nanoTime() < deadline) outer();
            reject(profiler, "event=cpu,signal=256", "signal must be in the range");
            reject(profiler, "event=wall,signal=42/256", "signal must be in the range");
            reject(profiler, "event=wall,signal=42/0", "signal must be in the range");
            reject(profiler, "event=cpu,signal=999999999999999999999", "signal must be in the range");
            reject(profiler, "event=wall,signal=42/-1", "signal must be in the range");
            reject(profiler, "event=cpu,wall=5ms,signal=42/42,jfr,file=" + directory.resolve("invalid.jfr"), "distinct signals");
            capture(profiler, directory.resolve("swapped.jfr"), "cpu", "26/27");
            capture(profiler, directory.resolve("upper.jfr"), "cpu", "77/255");
            capture(profiler, directory.resolve("cycles.jfr"), "cycles", "78/254");
        } finally {
            running.set(false);
            sleeper.interrupt();
            sleeper.join();
        }
    }
}
