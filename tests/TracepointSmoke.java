/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import one.profiler.AsyncProfiler;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public class TracepointSmoke {
    private static native void initialize();
    private static native void release();
    private static native void emit(int count, int id, int version, boolean named);
    private static void 燃烧𠮷(int count, int id, int version, boolean named) { emit(count, id, version, named); }
    private static void middle(int count, int id, int version, boolean named) { 燃烧𠮷(count, id, version, named); }
    private static void outer(int count, int id, int version, boolean named) { middle(count, id, version, named); }
    private static void 燃烧𠮷(String image) { System.load(image); }
    private static void middle(String image) { 燃烧𠮷(image); }
    private static void outer(String image) { middle(image); }
    private static void verifyResidentImages(int attempt) throws Exception {
        var directory = System.getProperty("asprof.tracepoint.images");
        if (directory == null || attempt != 1) return;
        var root = Path.of(directory);
        Files.writeString(root.resolve("images-loaded"), "ready");
        var deadline = System.nanoTime() + 20_000_000_000L;
        while (!Files.exists(root.resolve("images-checked"))) {
            if (System.nanoTime() >= deadline) throw new AssertionError("Driver did not verify resident image bases");
            Thread.sleep(10);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args[0].equals("foreign")) {
            System.load(args[1]); initialize(); emit(2048, 1, 7, false); release(); return;
        }
        var readyFile = System.getProperty("asprof.tracepoint.ready");
        if (readyFile != null) {
            var ready = Path.of(readyFile);
            var prepared = ready.resolveSibling("ready.tmp");
            Files.writeString(prepared, Long.toString(ProcessHandle.current().pid()));
            Files.move(prepared, ready, StandardCopyOption.ATOMIC_MOVE);
            var releaseFile = Path.of(System.getProperty("asprof.tracepoint.release"));
            var deadline = System.nanoTime() + 30_000_000_000L;
            while (!Files.exists(releaseFile)) {
                if (System.nanoTime() >= deadline) throw new AssertionError("Broker did not release provider target");
                Thread.sleep(20);
            }
        }
        System.load(args[1]); initialize();
        var profiler = AsyncProfiler.getInstance(args[0]);
        var output = Path.of(args[2]);
        var mode = args[3];
        for (int i = 0; i < 20000; ++i) outer(1, 1, 7, false);
        var iterations = mode.equals("restart") || mode.equals("kernel-restart") ? 2 : 1;
        var endpoint = System.getProperty("asprof.tracepoint.broker");
        var brokerOptions = endpoint == null ? "" : endpoint.isEmpty() ? ",fdtransfer" : ",fdtransfer=" + endpoint;
        for (int attempt = 0; attempt < iterations; ++attempt) {
            var recording = output.resolve("tracepoint-" + attempt + ".jfr");
            boolean named = mode.equals("named");
            boolean kernelImage = mode.startsWith("kernel-");
            int interval = mode.equals("interval") ? 7 : 1;
            String event = kernelImage ? "trace:{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}/5/0"
                : named ? "trace:{2a94e71b-655a-4f69-8c64-302d17032ae9}/@燃烧𠮷"
                : "trace:{e50fb813-9e08-40dc-a8af-3390db1dbbf4}/1/7";
            try {
                profiler.execute("start,event=" + event + ",alluser");
                profiler.execute("stop");
                throw new AssertionError("Provider alluser origin filtering was silently accepted");
            } catch (RuntimeException expected) {
                if (!expected.getMessage().contains("privilege-origin")) throw expected;
            }
            profiler.execute("start,event=" + event + ",interval=" + interval + ",cstack="
                + (mode.equals("java-only") ? "no" : "dwarf") + ",record-cpu,jfr,file=" + recording + brokerOptions);
            try {
                if (kernelImage) {
                    outer(args[4 + (mode.equals("kernel-restart") ? attempt : 0)]);
                    verifyResidentImages(attempt);
                }
                else {
                    outer(1024, 1, 7, named);
                    outer(128, 2, 7, named);
                }
                if (!named && !kernelImage) {
                    outer(128, 1, 8, false);
                    var foreign = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java.exe").toString(),
                        "-cp", System.getProperty("java.class.path"), TracepointSmoke.class.getName(), "foreign", args[1])
                        .inheritIO().start();
                    if (foreign.waitFor() != 0) throw new AssertionError("Foreign provider fixture failed");
                }
                if (mode.equals("interval")) {
                    var workers = new Thread[6];
                    for (int index = 0; index < workers.length; ++index) {
                        workers[index] = new Thread(() -> outer(1, 1, 7, false), "period-worker-" + index);
                        workers[index].start();
                    }
                    for (var worker : workers) worker.join();
                }
            } finally { profiler.execute("stop"); }
            var metrics = profiler.execute("metrics");
            Files.writeString(output.resolve("metrics-" + attempt + ".txt"), metrics, StandardCharsets.UTF_8);
            Files.writeString(Path.of(recording + ".collapsed"), profiler.execute("collapsed,total"), StandardCharsets.UTF_8);
            System.out.println("ATTEMPT=" + attempt + "\n" + metrics);
            int eligible = kernelImage ? 1 : mode.equals("interval") ? 1030 : 1024;
            if (!metrics.contains("windows_tracepoint_matched_events " + eligible + "\n")
                    || !metrics.contains("windows_tracepoint_failure 0\n")
                    || !metrics.contains("windows_tracepoint_events_lost 0\n")) throw new AssertionError("Tracepoint event identity/count/failure mismatch");
            if (endpoint != null && metrics.contains("windows_tracepoint_broker_pid 0\n")) throw new AssertionError("Provider bypassed requested broker");
            System.out.println("TRACEPOINT_RECORDING=" + recording);
        }
        release();
    }
}
