/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.lang.instrument.ClassDefinition;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import one.profiler.AsyncProfiler;
import one.profiler.Span;

public final class EtwClassChange {
    static Instrumentation instrumentation;
    static volatile byte[] replacement;
    static volatile boolean finished;
    static volatile Throwable workerFailure;
    static volatile CountDownLatch pauseEntered, pauseReleased;

    public static void premain(String arguments, Instrumentation value) {
        instrumentation = value;
        value.addTransformer(new ClassFileTransformer() {
            @Override
            public byte[] transform(ClassLoader loader, String name, Class<?> type,
                                    ProtectionDomain domain, byte[] bytes) {
                if (type == null || !name.equals("EtwJavaPayload")) return null;
                var entered = pauseEntered;
                if (entered != null) {
                    entered.countDown();
                    try {
                        if (!pauseReleased.await(15, TimeUnit.SECONDS)) throw new AssertionError("Class-change gate timed out");
                    } catch (InterruptedException failure) { Thread.currentThread().interrupt(); throw new RuntimeException(failure); }
                }
                var start = Span.start();
                try {
                    Thread.sleep(150);
                    return replacement;
                } catch (InterruptedException failure) {
                    Thread.currentThread().interrupt(); throw new RuntimeException(failure);
                } finally { Span.end(start, "class-change"); }
            }
        }, true);
    }

    static void runPayload() {
        try { while (!finished) EtwJavaPayload.burn(); }
        catch (Throwable failure) { workerFailure = failure; }
    }

    static void start(AsyncProfiler profiler, Path output) throws Exception {
        profiler.execute("start,event=etw:Timer,interval=1000000,cstack=dwarf,alluser,jfr,file=" + output);
    }

    static void save(AsyncProfiler profiler, Path output) throws Exception {
        Files.writeString(Path.of(output + ".collapsed"), profiler.execute("collapsed,total"));
        System.out.println(profiler.execute("metrics"));
    }

    static void finish(AsyncProfiler profiler, Path output) throws Exception {
        save(profiler, output);
        profiler.execute("start,event=cpu,interval=1000000");
        Thread.sleep(50);
        profiler.stop();
        var reset = profiler.execute("metrics");
        for (var metric : new String[] {"windows_java_methods", "windows_java_method_bytes", "windows_java_class_changes",
                                       "windows_java_active_class_changes", "windows_java_transition_pcs", "windows_java_mapping_unsafe"}) {
            if (!reset.contains(metric + " 0\n")) throw new AssertionError("Changed Java metadata retained after reset: " + reset);
        }
        System.out.println("JAVA_CLASS_CHANGE_RESET_OK");
        System.out.println("JAVA_CLASS_CHANGE_OK");
    }

    static void restartDuringChange(AsyncProfiler profiler, Path output, byte[] second, byte[] third) throws Exception {
        var restarted = Path.of(output + ".restart.jfr");
        var mutationFailure = new AtomicReference<Throwable>();
        var modifiers = new ArrayList<Thread>();
        EtwJavaPayload.burn();
        start(profiler, output);
        var capturing = true;
        var worker = new Thread(EtwClassChange::runPayload, "class-change-workload");
        worker.start();
        try {
            Thread.sleep(600);
            pauseEntered = new CountDownLatch(1);
            pauseReleased = new CountDownLatch(1);
            replacement = second;
            for (var i = 0; i < 2; i++) {
                var modifier = new Thread(() -> {
                    try { instrumentation.retransformClasses(EtwJavaPayload.class); }
                    catch (Throwable failure) { mutationFailure.compareAndSet(null, failure); }
                }, "overlapping-class-change-" + i);
                modifiers.add(modifier);
                modifier.start();
            }
            if (!pauseEntered.await(5, TimeUnit.SECONDS)) throw new AssertionError("No pending class change");
            var deadline = System.nanoTime() + 3_000_000_000L;
            while (!profiler.execute("metrics").contains("windows_java_active_class_changes 2\n")) {
                if (System.nanoTime() >= deadline) throw new AssertionError("Overlapping changes were not tracked");
                Thread.sleep(10);
            }
            Thread.sleep(100);
            profiler.stop();
            capturing = false;
            save(profiler, output);
            start(profiler, restarted);
            capturing = true;
            if (!profiler.execute("metrics").contains("windows_java_active_class_changes 2\n")) {
                throw new AssertionError("Active class changes were lost across recording reset");
            }
            pauseReleased.countDown();
            for (var modifier : modifiers) {
                modifier.join(5000);
                if (modifier.isAlive()) throw new AssertionError("Class change did not complete");
            }
            pauseEntered = null;
            pauseReleased = null;
            replacement = null;
            if (mutationFailure.get() != null) throw new AssertionError("Overlapping class change failed", mutationFailure.get());
            Thread.sleep(600);
            instrumentation.redefineClasses(new ClassDefinition(EtwJavaPayload.class, third));
            Thread.sleep(800);
        } finally {
            if (pauseReleased != null) pauseReleased.countDown();
            finished = true;
            for (var modifier : modifiers) modifier.join(5000);
            worker.join(5000);
            if (capturing) profiler.stop();
        }
        if (worker.isAlive() || workerFailure != null) throw new AssertionError("Restarted workload failed", workerFailure);
        finish(profiler, restarted);
        System.out.println("JAVA_CLASS_CHANGE_RESTART_OK");
    }

    public static void main(String[] args) throws Exception {
        var profiler = AsyncProfiler.getInstance(Path.of(args[0]).toAbsolutePath().toString());
        var output = Path.of(args[1]);
        var second = Files.readAllBytes(Path.of(args[2]));
        var third = Files.readAllBytes(Path.of(args[3]));
        if (args.length > 4) {
            restartDuringChange(profiler, output, second, third);
            return;
        }
        // Load the target before capture so its initial version is part of the
        // baseline, then keep obsolete invocations alive across both changes.
        EtwJavaPayload.burn();
        start(profiler, output);
        var worker = new Thread(EtwClassChange::runPayload, "class-change-workload");
        worker.start();
        try {
            Thread.sleep(800);
            instrumentation.redefineClasses(new ClassDefinition(EtwJavaPayload.class, second));
            Thread.sleep(800);
            replacement = third;
            instrumentation.retransformClasses(EtwJavaPayload.class);
            Thread.sleep(800);
            replacement = null;
            try {
                instrumentation.redefineClasses(new ClassDefinition(EtwJavaPayload.class, new byte[] {1,2,3}));
                throw new AssertionError("Invalid redefinition succeeded");
            } catch (ClassFormatError expected) { }
            replacement = new byte[] {1,2,3};
            try {
                instrumentation.retransformClasses(EtwJavaPayload.class);
                throw new AssertionError("Invalid retransformation succeeded");
            } catch (ClassFormatError expected) { }
            replacement = null;
            Thread.sleep(500);
        } finally {
            finished = true;
            worker.join(5000);
            profiler.stop();
        }
        if (worker.isAlive()) throw new AssertionError("Class-change workload did not stop");
        if (workerFailure != null) throw new AssertionError("Class-change workload failed", workerFailure);
        finish(profiler, output);
    }
}
