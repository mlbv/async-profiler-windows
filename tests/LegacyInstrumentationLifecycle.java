/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.concurrent.CountDownLatch;
import one.profiler.AsyncProfiler;
import one.profiler.Counter;

public final class LegacyInstrumentationLifecycle {
    private static volatile boolean rejectUndo;
    private static volatile int sink;
    private static CountDownLatch entered, release;

    public static void premain(String options, Instrumentation instrumentation) {
        instrumentation.addTransformer(new ClassFileTransformer() {
            public byte[] transform(ClassLoader loader, String name, Class<?> changed, ProtectionDomain domain, byte[] bytes) {
                return rejectUndo && name.equals("LegacyInstrumentationLifecycle$Target") ? new byte[] {1, 2, 3} : null;
            }
        }, true);
    }
    static final class Target { static void work() { sink++; } }
    static final class Other { static void work() { sink++; } }
    static void oldWork() throws InterruptedException { entered.countDown(); release.await(); }
    static void newWork() throws InterruptedException { Thread.sleep(15); }

    private static void expectRejected(AsyncProfiler profiler, String command) throws Exception {
        try {
            if (command.equals("stop")) profiler.stop(); else profiler.execute(command);
            throw new AssertionError("Unsafe instrumentation lifecycle action succeeded: " + command);
        } catch (IllegalStateException expected) {
            if (!expected.getMessage().contains("Cannot retransform classes for instrumentation")) throw expected;
        }
    }

    private static void recovery(AsyncProfiler profiler) throws Exception {
        Target.work(); Other.work();
        profiler.execute("start,event=LegacyInstrumentationLifecycle$Target.work");
        Target.work();
        rejectUndo = true;
        expectRejected(profiler, "stop");
        expectRejected(profiler, "start,event=cpu,interval=1000ms");
        expectRejected(profiler, "start,event=LegacyInstrumentationLifecycle$Other.work");
        String preserved = profiler.dumpCollapsed(Counter.SAMPLES);
        if (!preserved.contains("LegacyInstrumentationLifecycle$Target.work")) throw new AssertionError("Rejected start discarded previous data");
        rejectUndo = false;
        profiler.execute("start,event=cpu,interval=1000ms");
        try {
            Target.work(); Target.work(); Target.work();
            if (profiler.dumpCollapsed(Counter.SAMPLES).contains("LegacyInstrumentationLifecycle$Target.work")) {
                throw new AssertionError("Stale method probe entered CPU recording");
            }
        } finally { profiler.stop(); }
        profiler.execute("start,event=LegacyInstrumentationLifecycle$Other.work");
        try {
            Target.work(); Target.work(); Target.work();
            if (!profiler.dumpCollapsed(Counter.SAMPLES).isEmpty()) throw new AssertionError("Stale method probe entered different target recording");
            Other.work();
            String current = profiler.dumpCollapsed(Counter.SAMPLES);
            if (!current.contains("LegacyInstrumentationLifecycle$Other.work") || !current.trim().endsWith(" 1")) {
                throw new AssertionError("Recovered target did not record its call: " + current);
            }
        } finally { profiler.stop(); }
        System.out.println("INSTRUMENTATION_UNDO_RECOVERY_OK rejected=3 cpuAndMethodIsolation=true");
    }

    private static void inflight(AsyncProfiler profiler) throws Exception {
        for (boolean cpu : new boolean[] {true, false}) {
            entered = new CountDownLatch(1);
            release = new CountDownLatch(1);
            profiler.execute("start,trace=LegacyInstrumentationLifecycle.oldWork");
            Thread worker = new Thread(() -> {
                try { oldWork(); } catch (InterruptedException error) { throw new RuntimeException(error); }
            });
            worker.start();
            entered.await();
            profiler.stop();
            profiler.execute(cpu ? "start,event=cpu,interval=1000ms" : "start,trace=LegacyInstrumentationLifecycle.newWork");
            try {
                release.countDown();
                worker.join();
                String previous = profiler.dumpCollapsed(Counter.SAMPLES);
                if (previous.contains("LegacyInstrumentationLifecycle.oldWork")) throw new AssertionError("Obsolete frame entered new recording: " + previous);
                if (!cpu) {
                    if (!previous.isEmpty()) throw new AssertionError("Unexpected latency samples: " + previous);
                    newWork();
                    String current = profiler.dumpCollapsed(Counter.SAMPLES);
                    if (!current.contains("LegacyInstrumentationLifecycle.newWork") || !current.trim().endsWith(" 1")) {
                        throw new AssertionError("Current latency entry was lost: " + current);
                    }
                }
            } finally {
                release.countDown();
                worker.join();
                profiler.stop();
            }
        }
        System.out.println("INSTRUMENTATION_INFLIGHT_ISOLATION_OK cpuAndMethodIsolation=true currentLatency=1");
    }

    public static void main(String[] args) throws Exception {
        AsyncProfiler profiler = AsyncProfiler.getInstance(args[0]);
        if (args[1].equals("recovery")) recovery(profiler); else inflight(profiler);
    }
}
