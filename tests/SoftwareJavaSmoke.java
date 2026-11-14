/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.io.RandomAccessFile;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import one.profiler.AsyncProfiler;

/** Java page-fault and context-switch workloads with thread churn, for repeated software-event captures. */
public final class SoftwareJavaSmoke {
    static final int PAGE = 4096;
    static volatile long sink;

    static void sleeper(int count) throws InterruptedException {
        for (int i = 0; i < count; i++) Thread.sleep(1);
    }

    // A fresh private mapping makes the first write to each page a copy-on-write fault in compiled Java code.
    static void toucher(Path file, int pages) throws Exception {
        try (var raf = new RandomAccessFile(file.toFile(), "rw"); var channel = raf.getChannel()) {
            var map = channel.map(FileChannel.MapMode.PRIVATE, 0, (long) pages * PAGE);
            for (int i = 0; i < pages; i++) touch(map, i * PAGE);
        }
    }

    static void touch(MappedByteBuffer map, int offset) {
        map.put(offset, (byte) (map.get(offset) + 1));
    }

    static void churnWork(Path file) throws Exception {
        sleeper(4);
        toucher(file, 64);
    }

    static void churn(Path file, int batches) throws Exception {
        for (int batch = 0; batch < batches; batch++) {
            var workers = new ArrayList<Thread>();
            var failures = new ArrayList<Throwable>();
            for (int i = 0; i < 8; i++) {
                var worker = new Thread(() -> {
                    try { churnWork(file); }
                    catch (Throwable failure) { synchronized (failures) { failures.add(failure); } }
                }, "churn-" + batch + "-" + i);
                workers.add(worker);
                worker.start();
            }
            for (var worker : workers) worker.join();
            if (!failures.isEmpty()) throw new AssertionError("Churn worker failed", failures.get(0));
        }
    }

    static void workload(Path file, boolean faults) throws Exception {
        if (faults) toucher(file, 2048); else sleeper(256);
        churn(file, 4);
    }

    public static void main(String[] args) throws Exception {
        // agent output-directory endpoint(- for local) case...; each case is event:period[:options]
        var directory = Path.of(args[1]);
        var file = directory.resolve("mapped.bin");
        try (var raf = new RandomAccessFile(file.toFile(), "rw")) { raf.setLength(2048L * PAGE); }
        for (int i = 0; i < 40; i++) { toucher(file, 64); sleeper(8); churnWork(file); }
        var ready = directory.resolve("ready");
        var release = directory.resolve("release");
        var prepared = directory.resolve("ready.tmp");
        Files.writeString(prepared, Long.toString(ProcessHandle.current().pid()));
        Files.move(prepared, ready, StandardCopyOption.ATOMIC_MOVE);
        var deadline = System.nanoTime() + 60_000_000_000L;
        while (!Files.exists(release)) {
            if (System.nanoTime() >= deadline) throw new AssertionError("Driver did not release target");
            Thread.sleep(20);
        }
        var profiler = AsyncProfiler.getInstance(Path.of(args[0]).toAbsolutePath().toString());
        var transport = args[2].equals("-") ? "" : args[2].isEmpty() ? ",fdtransfer" : ",fdtransfer=" + args[2];
        for (int index = 3; index < args.length; index++) {
            var parts = args[index].split(":", 3);
            var event = parts[0];
            var options = parts.length > 2 ? "," + parts[2] : "";
            var base = directory.resolve((index - 3) + "-" + event + "-p" + parts[1]).toString();
            profiler.execute("start,event=" + event + ",interval=" + parts[1] + options + transport + ",jfr,file=" + base + ".jfr");
            workload(file, event.equals("page-faults"));
            profiler.stop();
            Files.writeString(Path.of(base + ".jfr.collapsed"), profiler.execute("collapsed,total"));
            Files.writeString(Path.of(base + ".samples.collapsed"), profiler.execute("collapsed,samples"));
            profiler.execute("otlp,total,file=" + base + ".native.otlp");
            Files.writeString(Path.of(base + ".metrics"), profiler.execute("metrics"));
            System.out.println("CAPTURE_DONE " + (index - 3) + " " + args[index]);
        }
        System.out.println("SOFTWARE_JAVA_CAPTURES_OK captures=" + (args.length - 3));
    }
}
