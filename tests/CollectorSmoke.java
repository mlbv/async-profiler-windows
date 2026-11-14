/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.lang.ref.WeakReference;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import one.profiler.AsyncProfiler;

public final class CollectorSmoke {
    static final List<byte[]> roots = new ArrayList<>();
    static final Object monitor = new Object();
    static final ReentrantLock lock = new ReentrantLock();
    static volatile long result;
    static volatile boolean allocating;
    static volatile Object concurrentSink;
    static volatile long concurrentAllocations;

    static byte[] allocateRetained() {
        byte[] object = new byte[64 * 1024];
        object[0] = 1;
        roots.add(object);
        return object;
    }

    static WeakReference<byte[]> allocateDiscarded() {
        byte[] object = new byte[64 * 1024];
        object[0] = 2;
        return new WeakReference<>(object);
    }

    static void allocateLarge() { result += new byte[2 * 1024 * 1024].length; }
    static void allocateConcurrentDiscarded() { concurrentSink = new byte[8192]; concurrentAllocations++; }
    // C2 code refills TLABs through a runtime stub, whose frame is the JavaFrameAnchor's
    static void allocateCompiled() { concurrentSink = new byte[8192]; }

    static void collect(List<WeakReference<byte[]>> refs) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (System.nanoTime() < deadline) {
            System.gc();
            int remaining = 0;
            for (WeakReference<byte[]> ref : refs) if (ref.get() != null) remaining++;
            if (remaining == 0) {
                System.out.println("COLLECTED_WEAK_OBJECTS " + refs.size());
                return;
            }
            Thread.sleep(25);
        }
        throw new AssertionError("Allocated objects remained strongly reachable");
    }

    static void allocations(boolean live) throws Exception {
        List<WeakReference<byte[]>> discarded = new ArrayList<>();
        for (int i = 0; i < 64; i++) {
            allocateRetained();
            discarded.add(allocateDiscarded());
        }
        if (live) collect(discarded);
        else for (int i = 0; i < 8; i++) allocateLarge();
        if (roots.size() != 64) throw new AssertionError("Retained workload count changed");
        for (byte[] object : roots) if (object[0] != 1) throw new AssertionError("Retained object changed");
    }

    static void releaseRoots() throws Exception {
        List<WeakReference<byte[]>> refs = new ArrayList<>();
        for (byte[] object : roots) refs.add(new WeakReference<>(object));
        roots.clear();
        collect(refs);
    }

    static void contendMonitor() { synchronized (monitor) { result++; } }
    static void contendLock() { lock.lock(); try { result++; } finally { lock.unlock(); } }
    static void contendTimedLock() throws Exception {
        if (lock.tryLock(25, TimeUnit.MILLISECONDS)) {
            lock.unlock();
            throw new AssertionError("Timed lock unexpectedly acquired");
        }
    }

    static void locks() throws Exception {
        for (int i = 0; i < 8; i++) {
            final CountDownLatch monitorReady = new CountDownLatch(1);
            Thread holder = new Thread(() -> {
                synchronized (monitor) {
                    monitorReady.countDown();
                    try { Thread.sleep(40); } catch (InterruptedException e) { throw new AssertionError(e); }
                }
            }, "collector-monitor-holder");
            holder.start();
            monitorReady.await();
            contendMonitor();
            holder.join();
            for (int timed = 0; timed < 2; timed++) {
                final CountDownLatch lockReady = new CountDownLatch(1);
                holder = new Thread(() -> {
                    lock.lock();
                    try {
                        lockReady.countDown();
                        Thread.sleep(60);
                    } catch (InterruptedException e) { throw new AssertionError(e); }
                    finally { lock.unlock(); }
                }, "collector-lock-holder");
                holder.start();
                lockReady.await();
                if (timed == 0) contendLock(); else contendTimedLock();
                holder.join();
            }
        }
    }

    static void wallSleep(CountDownLatch ready) {
        long warm = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(50);
        long value = 0;
        while (System.nanoTime() < warm) value++;
        result = value;
        ready.countDown();
        try { Thread.sleep(5000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    static void wallBusy() {
        long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
        long value = result;
        while (System.nanoTime() < end) {
            for (int i = 0; i < 100_000; i++) value = Long.rotateLeft(value ^ i, 13) * 0x100000001b3L;
        }
        result = value;
    }

    public static void main(String[] args) throws Exception {
        AsyncProfiler profiler = AsyncProfiler.getInstance(args[0]);
        Thread.currentThread().setName("collector-main");
        allocateRetained();
        allocateDiscarded();
        roots.clear();
        String mode = args[2];
        boolean wall = mode.startsWith("wall");
        boolean live = mode.startsWith("live");
        for (int round = 0; round < (mode.equals("live") || mode.equals("live-concurrent") || mode.equals("wall-resume") ? 2 : 1); round++) {
            String file = args[1] + (round == 0 || wall ? "" : ".restart.jfr");
            String options = wall ? mode.equals("wall-cancel") ? "event=wall,interval=3600s,filter" : mode.equals("wall-supplementary") || round != 0
                    ? "event=cpu,interval=1ms,wall=7ms,filter" : "event=wall,interval=5ms,filter"
                    : mode.equals("lock") ? "event=lock,lock=1us"
                    : mode.equals("live-mixed") ? "event=cpu,interval=10ms,alloc=4k,live"
                    : "event=alloc,alloc=4k" + (live ? ",live" : mode.equals("tlab") ? ",tlab" : "");
            final CountDownLatch sleeperReady = new CountDownLatch(1);
            Thread sleeper = new Thread(() -> wallSleep(sleeperReady), "collector-sleeper");
            Thread allocator = null;
            if (wall) { sleeper.start(); sleeperReady.await(); }
            if (mode.equals("tlab")) for (int i = 0; i < 20_000; i++) allocateCompiled();
            profiler.execute((wall && round != 0 ? "resume," : "start,") + options + ",cstack=vm,jfr,file=" + file);
            try {
                if (wall) {
                    profiler.addThread(Thread.currentThread());
                    profiler.addThread(sleeper);
                    if (mode.equals("wall-cancel")) Thread.sleep(100); else wallBusy();
                    if (round != 0) { profiler.execute("dump,jfr"); wallBusy(); }
                } else if (mode.equals("lock")) locks();
                else {
                    allocations(live);
                    if (mode.equals("tlab")) for (int i = 0; i < 20_000; i++) allocateCompiled();
                    if (mode.equals("live-mixed")) wallBusy();
                    if (mode.equals("live-concurrent")) {
                        allocating = true;
                        concurrentAllocations = 0;
                        allocator = new Thread(() -> { while (allocating) allocateConcurrentDiscarded(); }, "collector-allocator");
                        allocator.setDaemon(true);
                        allocator.start();
                        Thread.sleep(250);
                        if (concurrentAllocations < 100) throw new AssertionError("Concurrent allocation path did not run");
                    }
                }
            } finally {
                long stopStart = System.nanoTime();
                try { profiler.stop(); }
                finally {
                    allocating = false;
                    if (allocator != null) allocator.join();
                    concurrentSink = null;
                }
                long stopNanos = System.nanoTime() - stopStart;
                if (sleeper.isAlive()) { sleeper.interrupt(); sleeper.join(); }
                if (mode.equals("wall-cancel")) {
                    if (stopNanos > TimeUnit.MILLISECONDS.toNanos(250)) throw new AssertionError("Wall timer cancellation was slow: " + stopNanos);
                    System.out.println("WALL_CANCEL_OK stopNs=" + stopNanos);
                }
            }
            Files.write(Paths.get(file + ".collapsed"), profiler.execute("collapsed,total").getBytes(StandardCharsets.UTF_8));
            if (live) releaseRoots();
        }
        System.out.println("COLLECTOR_OK " + mode + " java=" + System.getProperty("java.version"));
    }
}
