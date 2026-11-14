/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import jdk.jfr.consumer.RecordingFile;
import one.profiler.AsyncProfiler;

public final class AsyncJavaSmoke {
    static volatile long result;
    static java.lang.reflect.Method nativeWork;

    static void leaf() {
        var value = result;
        for (var i = 0; i < 100_000; i++) value = Long.rotateLeft(value + i, 7);
        result = value;
    }

    static void outer() { leaf(); }

    static void work(long millis) {
        var deadline = System.nanoTime() + millis * 1_000_000L;
        while (System.nanoTime() < deadline) outer();
    }

    static void registryChurn(AsyncProfiler profiler, int count) throws Exception {
        if (count == 0) { work(1000); return; }
        if (count < 1 || count > 64) throw new IllegalArgumentException("Registry churn count must be 1..64");
        var failure = new java.util.concurrent.atomic.AtomicReference<Throwable>();
        var completed = new java.util.concurrent.atomic.AtomicInteger();
        var workers = new java.util.ArrayList<Thread>();
        for (var i = 0; i < count; i++) {
            var worker = new Thread(() -> {
                try {
                    profiler.addThread(Thread.currentThread());
                    work(150);
                    Thread.sleep(250);
                    work(150);
                } catch (Throwable error) { failure.compareAndSet(null, error); }
                finally { completed.incrementAndGet(); }
            }, "agct-registry-churn-" + i);
            workers.add(worker);
            worker.start();
        }
        work(1000);
        for (var worker : workers) {
            worker.join(5000);
            if (worker.isAlive()) throw new AssertionError("Registry churn worker did not exit");
        }
        if (failure.get() != null || completed.get() != count) throw new AssertionError("Registry churn did not complete", failure.get());
        System.out.println("REGISTRY_CHURN_BIRTHS completed=" + completed.get());
    }

    static Map<String, Long> metrics(AsyncProfiler profiler) throws Exception {
        var values = new HashMap<String, Long>();
        for (var line : profiler.execute("metrics").split("\n")) {
            var words = line.split(" ");
            if (words.length == 2 && words[0].startsWith("windows_agct_")) values.put(words[0], Long.parseLong(words[1]));
        }
        return values;
    }

    static void capture(AsyncProfiler profiler, Path file, String options) throws Exception {
        profiler.execute("start,jfr,file=" + file + ",interval=1ms,filter," + options);
        profiler.addThread(Thread.currentThread());
        try { work(1500); }
        finally { profiler.stop(); }
        Files.writeString(Path.of(file + ".collapsed"), profiler.execute("collapsed,total"));
        ReadCounters.main(new String[]{file.toString(), file + ".collapsed", "ns"});
        var complete = 0;
        for (var event : RecordingFile.readAllEvents(file)) {
            if (!event.getEventType().getName().equals("jdk.ExecutionSample") || event.getStackTrace() == null) continue;
            var leaf = false;
            var outer = false;
            var work = false;
            var main = false;
            for (var frame : event.getStackTrace().getFrames()) {
                var method = frame.getMethod();
                if (!method.getType().getName().equals("AsyncJavaSmoke")) continue;
                leaf |= method.getName().equals("leaf");
                outer |= method.getName().equals("outer");
                work |= method.getName().equals("work");
                main |= method.getName().equals("main");
            }
            if (leaf && outer && work && main) complete++;
        }
        if (complete < 10) throw new AssertionError("Lost async Java workload callers: " + complete);
        System.out.println(options + " complete=" + complete + " " + metrics(profiler));
    }

    static void callNative() throws Exception { nativeWork.invoke(null, 1); }

    static void captureNative(AsyncProfiler profiler, Path file, String fixture) throws Exception {
        System.load(Path.of(fixture).toAbsolutePath().toString());
        nativeWork = NativeWindowFixture.class.getDeclaredMethod("run", int.class);
        nativeWork.setAccessible(true);
        profiler.execute("start,event=cpu,interval=1ms,cstack=dwarf,features=agct+jnienv+pcaddr,jfr,file=" + file);
        try { callNative(); work(500); }
        finally { profiler.stop(); }
        Files.writeString(Path.of(file + ".collapsed"), profiler.execute("collapsed,total"));
        ReadCounters.main(new String[]{file.toString(), file + ".collapsed", "ns"});
        var javaAndNative = 0;
        var nativeOnly = 0;
        for (var event : RecordingFile.readAllEvents(file)) {
            if (!event.getEventType().getName().equals("jdk.ExecutionSample") || event.getStackTrace() == null) continue;
            var nativeBurn = false;
            var javaRun = false;
            var javaCaller = false;
            for (var frame : event.getStackTrace().getFrames()) {
                var method = frame.getMethod();
                nativeBurn |= method.getName().contains("WindowInsideBusy");
                javaRun |= method.getType().getName().equals("NativeWindowFixture") && method.getName().equals("run");
                javaCaller |= method.getType().getName().equals("AsyncJavaSmoke") && method.getName().equals("callNative");
            }
            if (nativeBurn) {
                if (javaRun || javaCaller) {
                    if (!javaRun || !javaCaller) throw new AssertionError("Native and Java callers disagree: " + event);
                    javaAndNative++;
                } else nativeOnly++;
            }
        }
        if (javaAndNative < 10 || nativeOnly == 0) throw new AssertionError("Missing native/Java or native-only workload: " + javaAndNative + "/" + nativeOnly);
        System.out.println("mixedContext javaAndNative=" + javaAndNative + " nativeOnly=" + nativeOnly + " " + metrics(profiler));
    }

    public static void main(String[] args) throws Exception {
        var profiler = AsyncProfiler.getInstance(Path.of(args[0]).toAbsolutePath().toString());
        var directory = Path.of(args[1]);
        work(500);
        capture(profiler, directory.resolve("agct.jfr"), "event=cpu,cstack=no,features=agct+jnienv");
        var calls = metrics(profiler).get("windows_agct_calls");
        if (calls < 10) throw new AssertionError("Forced AGCT never called the JVM walker: " + calls);
        var checkedEnvs = metrics(profiler).get("windows_agct_jnienv_checks");
        if (checkedEnvs < 10 || !checkedEnvs.equals(calls)) throw new AssertionError("AGCT did not validate real target JNIEnv: " + checkedEnvs + "/" + calls);
        capture(profiler, directory.resolve("vm.jfr"), "event=cpu,cstack=no");
        if (!metrics(profiler).get("windows_agct_calls").equals(calls)) throw new AssertionError("Default Java-only sampling unexpectedly called AGCT");
        if (!metrics(profiler).get("windows_agct_jnienv_checks").equals(checkedEnvs)) throw new AssertionError("Default sampler unexpectedly entered target-thread JNIEnv validation");

        var running = new AtomicBoolean(true);
        var sleeper = new Thread(() -> {
            while (running.get()) {
                try { Thread.sleep(250); }
                catch (InterruptedException ignored) { return; }
                outer();
            }
        }, "agct-nonalertable-sleeper");
        sleeper.start();
        var churn = Integer.getInteger("asprof.test.registryChurn", 0);
        try {
            profiler.execute("start,event=wall,interval=1ms,cstack=no,features=agct,filter,jfr,file=" + directory.resolve("wall.jfr"));
            profiler.addThread(Thread.currentThread());
            profiler.addThread(sleeper);
            try { registryChurn(profiler, churn); }
            finally { profiler.stop(); }
        } finally {
            running.set(false);
            sleeper.interrupt();
            sleeper.join();
        }
        if (churn > 0) {
            var churnSamples = 0;
            var churnJava = 0;
            for (var event : RecordingFile.readAllEvents(directory.resolve("wall.jfr"))) {
                if (!event.getEventType().getName().equals("profiler.WallClockSample")) continue;
                var thread = event.getThread("sampledThread");
                if (thread != null && ((thread.getJavaName() != null && thread.getJavaName().startsWith("agct-registry-churn-"))
                        || (thread.getOSName() != null && thread.getOSName().startsWith("agct-registry-churn-")))) {
                    churnSamples++;
                    if (event.getStackTrace() != null && event.getStackTrace().getFrames().stream().anyMatch(frame ->
                            frame.getMethod().getType().getName().equals("AsyncJavaSmoke")
                            && frame.getMethod().getName().equals("leaf"))) churnJava++;
                }
            }
            if (churnSamples == 0 || churnJava == 0) throw new AssertionError("No positive contextual Java stack observed a churn thread: " + churnSamples + "/" + churnJava);
            System.out.println("REGISTRY_CHURN_SAMPLES total=" + churnSamples + " positiveJava=" + churnJava);
        }
        var stopped = metrics(profiler);
        work(300);
        var drained = metrics(profiler);
        if (!drained.get("windows_agct_calls").equals(stopped.get("windows_agct_calls"))) throw new AssertionError("AGCT callback executed after stop");
        if (drained.get("windows_agct_apc_failures") != 0 || drained.get("windows_agct_apcs_pending") != 0) {
            throw new AssertionError("APC request failed or outlived its target: " + drained);
        }
        if (drained.get("windows_agct_apc_timeouts") == 0) throw new AssertionError("Non-alertable wait did not exercise cancellation: " + drained);
        System.out.println("cancelledAndDrained=" + drained);
        capture(profiler, directory.resolve("agct-restart.jfr"), "event=cpu,cstack=no,features=agct");
        if (metrics(profiler).get("windows_agct_calls") <= drained.get("windows_agct_calls")) throw new AssertionError("AGCT did not restart");
        if (args.length > 2) captureNative(profiler, directory.resolve("agct-native.jfr"), args[2]);
    }
}
