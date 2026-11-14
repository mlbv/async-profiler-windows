/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import one.profiler.AsyncProfiler;

public final class BrokerJavaSmoke {
    static long metric(String metrics, String key) {
        var prefix = key + " ";
        return metrics.lines().filter(line -> line.startsWith(prefix))
                .mapToLong(line -> Long.parseLong(line.substring(prefix.length()))).findFirst().orElseThrow();
    }
    public static void main(String[] args) throws Exception {
        var ready = Path.of(args[3]);
        var release = Path.of(args[4]);
        var prepared = ready.resolveSibling("ready.tmp");
        Files.writeString(prepared, Long.toString(ProcessHandle.current().pid()));
        Files.move(prepared, ready, StandardCopyOption.ATOMIC_MOVE);
        var deadline = System.nanoTime() + 30_000_000_000L;
        while (!Files.exists(release)) {
            if (System.nanoTime() >= deadline) throw new AssertionError("Broker did not release target");
            Thread.sleep(20);
        }
        if (Boolean.getBoolean("asprof.etw.verify.empty")) {
            var profiler = AsyncProfiler.getInstance(Path.of(args[0]).toAbsolutePath().toString());
            try {
                profiler.execute("start,event=cpu,fdtransfer=");
                throw new AssertionError("Explicit empty fdtransfer was accepted");
            } catch (RuntimeException failure) {
                if (!failure.getMessage().contains("fdtransfer path must not be empty")) throw failure;
                System.out.println("EMPTY_FDTRANSFER_REJECTED");
            }
        }
        if (args[2].equals("loop") || args[2].endsWith("-death")) {
            var collectorDeath = args[2].equals("broker-death") || args[2].equals("bootstrap-death");
            var profiler = AsyncProfiler.getInstance(Path.of(args[0]).toAbsolutePath().toString());
            EtwJavaSmoke.work(1000);
            var interval = Long.getLong("asprof.etw.interval", 1_000_000L);
            var endpoint = System.getProperty("asprof.etw.broker");
            var options = endpoint.isEmpty() ? ",fdtransfer" : ",fdtransfer=" + endpoint;
            var output = args[1];
            if (args[2].equals("loop")) { options += ",timeout=3,loop=1"; output += "-%n.jfr"; }
            profiler.execute("start,event=etw:Timer,interval=" + interval + ",cstack=dwarf,alluser,jfr,file=" + output + options);
            Files.writeString(ready.resolveSibling("active"), profiler.execute("metrics"));
            var captureDeadline = System.nanoTime() + 15_000_000_000L;
            if (args[2].equals("loop")) {
                while (profiler.execute("status").contains("is running")) {
                    if (System.nanoTime() >= captureDeadline) throw new AssertionError("Broker loop did not expire");
                    EtwJavaSmoke.work(50);
                }
                System.out.println("BROKER_LOOP_COMPLETED");
            } else {
                var sampled = false;
                while (!Files.exists(ready.resolveSibling("finish"))) {
                    if (System.nanoTime() >= captureDeadline) throw new AssertionError("Driver did not finish death test");
                    EtwJavaSmoke.work(50);
                    if (collectorDeath && !sampled) {
                        var metrics = profiler.execute("metrics");
                        if (metric(metrics, "windows_etw_samples") > 0) {
                            Files.writeString(ready.resolveSibling("sampled"), metrics);
                            sampled = true;
                        }
                    }
                }
                var firstFailure = 0L;
                if (collectorDeath) {
                    while ((firstFailure = metric(profiler.execute("metrics"), "windows_etw_failure")) == 0) {
                        if (System.nanoTime() >= captureDeadline) throw new AssertionError("Broker death did not reach consumer");
                        Thread.sleep(10);
                    }
                    System.out.println("BROKER_FATAL_FIRST " + firstFailure);
                }
                var fatalStop = false;
                try { profiler.stop(); }
                catch (IllegalStateException failure) {
                    if (!collectorDeath || !failure.getMessage().contains("Windows error " + firstFailure)) throw failure;
                    System.out.println("BROKER_FATAL_STOP " + failure.getMessage());
                    fatalStop = true;
                }
                if (collectorDeath && !fatalStop) throw new AssertionError("Broker death did not fail stop");
                Files.writeString(Path.of(output + ".collapsed"), profiler.execute("collapsed,total"));
            }
            System.out.println(profiler.execute("metrics"));
        } else {
            EtwJavaSmoke.main(new String[] {args[0], args[1], args[2]});
        }
    }
}
