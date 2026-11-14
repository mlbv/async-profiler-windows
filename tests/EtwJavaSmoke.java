/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Files;
import java.nio.file.Path;
import one.profiler.AsyncProfiler;
import java.lang.ref.WeakReference;
import java.lang.ref.ReferenceQueue;
import java.util.ArrayList;

public final class EtwJavaSmoke {
    static volatile long result;
    static volatile double floating = 0.25;
    static volatile Object missing;
    static volatile int divisor;
    static volatile int index = -1;
    static final int[] values = new int[1];
    static final ArrayList<ClassLoader> retainedLoaders = new ArrayList<>();
    static void throwing() {
        for (var i = 0; i < 64; i++) {
            try { result += missing.hashCode(); } catch (NullPointerException expected) { }
            try { result += 100 / divisor; } catch (ArithmeticException expected) { }
            try { result += values[index]; } catch (ArrayIndexOutOfBoundsException expected) { }
        }
    }
    static void 燃烧𠮷() {
        var value = result;
        for (var i = 0; i < 100_000; i++) value = Long.rotateLeft(value ^ i, 13) * 0x100000001b3L;
        result = value;
    }
    static void middle() { 燃烧𠮷(); }
    static void outer() { middle(); }
    static long adapterTarget(long value) { return Long.rotateLeft(value ^ 0x51ed270bL, 7) * 0x100000001b3L; }
    static void adapters(long millis) {
        var end = System.nanoTime() + millis * 1_000_000L;
        var value = result;
        while (System.nanoTime() < end) {
            for (var i = 0; i < 1000; i++) value = adapterTarget(value);
        }
        result = value;
    }
    static void unprovenTarget() {
        var value = floating;
        for (var i = 0; i < 100_000; i++) value = value * 1.000000001 + 0.12345;
        floating = value;
    }
    static void unprovenWork(long millis) {
        var end = System.nanoTime() + millis * 1_000_000L;
        while (System.nanoTime() < end) unprovenTarget();
    }
    static void unprovenFmaTarget() {
        var value = floating;
        for (var i = 0; i < 100_000; i++) value = Math.fma(value, 1.000000001, 0.12345);
        floating = value;
    }
    static void unprovenFmaWork(long millis) {
        var end = System.nanoTime() + millis * 1_000_000L;
        while (System.nanoTime() < end) unprovenFmaTarget();
    }
    static void work(long millis) {
        var end = System.nanoTime() + millis * 1_000_000L;
        while (System.nanoTime() < end) outer();
    }
    static final class PayloadLoader extends ClassLoader {
        PayloadLoader() { super(null); }
        Class<?> define(byte[] bytes) { return defineClass("EtwJavaPayload", bytes, 0, bytes.length); }
    }
    static WeakReference<ClassLoader> payload(byte[] bytes, ReferenceQueue<ClassLoader> queue) throws Exception {
        var loader = new PayloadLoader();
        loader.define(bytes).getMethod("burn").invoke(null);
        return new WeakReference<>(loader, queue);
    }
    static void unloading() throws Exception {
        byte[] bytes;
        try (var stream = EtwJavaSmoke.class.getResourceAsStream("/EtwJavaPayload.class")) { bytes = stream.readAllBytes(); }
        var loaders = new ArrayList<WeakReference<ClassLoader>>();
        var queue = new ReferenceQueue<ClassLoader>();
        for (var i = 0; i < 8; i++) loaders.add(payload(bytes, queue));
        var unloaded = 0;
        // Compiler tasks may temporarily retain their defining loaders. The
        // unprofiled GraalVM baseline also exceeds a few immediate GC cycles.
        var deadline = System.nanoTime() + 10_000_000_000L;
        while (unloaded < loaders.size() && System.nanoTime() < deadline) {
            System.gc();
            Thread.sleep(100);
            while (queue.poll() != null) unloaded++;
        }
        if (unloaded != loaders.size()) throw new AssertionError("Payload class loaders retained: " + (loaders.size() - unloaded));
        System.out.println("UNLOADED_LOADERS " + unloaded);
    }
    static void reflecting() throws Exception {
        byte[] bytes;
        try (var stream = EtwJavaSmoke.class.getResourceAsStream("/EtwJavaPayload.class")) { bytes = stream.readAllBytes(); }
        for (var i = 0; i < 8; i++) {
            var loader = new PayloadLoader();
            retainedLoaders.add(loader);
            loader.define(bytes).getMethod("burn").invoke(null);
        }
    }
    static void record(AsyncProfiler profiler, Path output, String mode) throws Exception {
        var event = System.getProperty("asprof.etw.event", mode.equals("cpu") || mode.endsWith("-cpu") ? "cpu" : "etw:Timer");
        var features = System.getProperty("asprof.etw.features", "");
        var cstack = mode.startsWith("java-only") ? "no" : features.contains("mixed") ? "vm" : "dwarf";
        var options = mode.equals("java-only-cpu-id") ? ",record-cpu" : mode.equals("kernel") ? "" : ",alluser";
        if (!features.isEmpty()) options += ",features=" + features;
        var broker = System.getProperty("asprof.etw.broker");
        if (broker != null) options += broker.isEmpty() ? ",fdtransfer" : ",fdtransfer=" + broker;
        var interval = System.getProperty("asprof.etw.interval", "1000000");
        var intervalOption = interval.equals("default") ? "" : ",interval=" + interval;
        try { profiler.execute("start,event=" + event + intervalOption + ",cstack=" + cstack + options + ",jfr,file=" + output); }
        catch (RuntimeException failure) { System.err.println(profiler.execute("metrics")); throw failure; }
        if (mode.equals("exit")) { work(500); System.exit(0); }
        try {
            if (mode.equals("unload")) unloading();
            else if (mode.startsWith("reflect")) reflecting();
            else if (mode.equals("exceptions")) {
                var end = System.nanoTime() + 2_500_000_000L;
                while (System.nanoTime() < end) { throwing(); outer(); }
            }
            else if (mode.equals("adapters")) adapters(2500);
            else if (mode.equals("scalar")) unprovenWork(2500);
            else if (mode.equals("unproven")) unprovenFmaWork(2500);
            else work(2500);
        } finally { profiler.stop(); retainedLoaders.clear(); }
        Files.writeString(Path.of(output + ".collapsed"), profiler.execute("collapsed,total"));
        System.out.println(profiler.execute("metrics"));
        if (System.getProperty("asprof.etw.event") != null) {
            var sources = profiler.execute("list");
            if (sources.contains("asprof-raw-")) throw new AssertionError("Transient raw PMU source remained registered: " + sources);
            System.out.println("RAW_PMU_SOURCE_REMOVED");
        }
    }
    public static void main(String[] args) throws Exception {
        if (args.length > 2 && args[2].equals("unload-baseline")) {
            work(1000); unloading(); return;
        }
        var profiler = AsyncProfiler.getInstance(Path.of(args[0]).toAbsolutePath().toString());
        var output = Path.of(args[1]).toAbsolutePath();
        if (Boolean.getBoolean("asprof.etw.verify.features")) {
            for (var feature : new String[]{"vtable", "comptask"}) {
                try {
                    profiler.execute("start,event=etw:Timer,features=" + feature);
                    throw new AssertionError("ETW silently accepted unavailable sampled state: " + feature);
                } catch (RuntimeException failure) {
                    if (!failure.getMessage().contains(feature + " feature requires")
                            || !failure.getMessage().contains("unavailable in ETW stack events")) throw failure;
                }
            }
            System.out.println("ETW_SAMPLED_STATE_FEATURES_REJECTED");
        }
        work(1000);
        if (args.length > 2 && args[2].equals("adapters")) adapters(500);
        if (args.length > 2 && args[2].equals("scalar")) unprovenWork(500);
        if (args.length > 2 && args[2].equals("unproven")) unprovenFmaWork(500);
        if (args.length > 2 && args[2].equals("warm-only")) return;
        record(profiler, output, args.length > 2 ? args[2] : "plain");
        if (args.length > 2 && args[2].startsWith("restart")) {
            var second = args[2].equals("restart") ? "unload" : args[2].substring("restart-".length());
            record(profiler, Path.of(output + ".restart.jfr"), second);
            profiler.execute("start,event=cpu,interval=1000000");
            Thread.sleep(50);
            profiler.stop();
            var metrics = profiler.execute("metrics");
            if (!metrics.contains("windows_java_methods 0\n") || !metrics.contains("windows_java_method_bytes 0\n")) {
                throw new AssertionError("Java metadata retained after recording reset: " + metrics);
            }
            System.out.println("METADATA_RESET_OK");
        }
    }
}
