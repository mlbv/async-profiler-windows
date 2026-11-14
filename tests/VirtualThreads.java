/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReentrantLock;
import one.profiler.AsyncProfiler;
import one.profiler.Span;

/** Virtual threads burning CPU under a contended monitor and a contended ReentrantLock, each iteration a span. */
public final class VirtualThreads {
    static final Object MONITOR = new Object();
    static final ReentrantLock LOCK = new ReentrantLock();
    static final int THREADS = 16, ITERATIONS = 50;
    static volatile long sink;

    static long vtBurn(long nanos) {
        long end = System.nanoTime() + nanos, value = 1;
        while (System.nanoTime() < end) for (int i = 0; i < 10000; i++) value = value * 31 + i;
        return value;
    }

    static void vtMonitor() {
        synchronized (MONITOR) { sink += vtBurn(2_000_000); }
    }

    static void vtPark() {
        LOCK.lock();
        try { sink += vtBurn(2_000_000); } finally { LOCK.unlock(); }
    }

    public static void main(String[] args) throws Exception {
        AsyncProfiler profiler = AsyncProfiler.getInstance(Path.of(args[0]).toAbsolutePath().toString());
        profiler.execute("start,event=cpu,interval=1ms,lock=0,jfr,file=" + args[1]);
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            for (int thread = 0; thread < THREADS; thread++) {
                executor.submit(() -> {
                    for (int i = 0; i < ITERATIONS; i++) {
                        long start = Span.start();
                        if ((i & 1) == 0) vtMonitor(); else vtPark();
                        Span.end(start, "vt-span");
                    }
                    return null;
                });
            }
        }
        profiler.stop();
        System.out.println("VIRTUAL_THREADS_DONE spans=" + THREADS * ITERATIONS);
    }
}
