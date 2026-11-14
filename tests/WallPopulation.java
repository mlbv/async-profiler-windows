/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import one.profiler.AsyncProfiler;

public final class WallPopulation {
    static final int BUSY_THREADS = 3;
    static volatile boolean running = true;
    static volatile long sink;

    static void wallBusy(CountDownLatch ready) {
        ready.countDown();
        long value = 1;
        while (running) {
            for (int i = 0; i < 100_000; i++) value = Long.rotateLeft(value ^ i, 13) * 0x100000001b3L;
            sink = value;
        }
    }

    static void wallSleep(CountDownLatch ready, CountDownLatch release) {
        long end = System.nanoTime() + 50_000_000L;
        long value = 0;
        while (System.nanoTime() < end) value++;
        sink = value;
        ready.countDown();
        try { release.await(); }
        catch (InterruptedException error) { throw new AssertionError(error); }
    }

    public static void main(String[] args) throws Exception {
        AsyncProfiler profiler = AsyncProfiler.getInstance(args[0]);
        Path recording = Path.of(args[1]);
        boolean nobatch = Boolean.parseBoolean(args[2]);
        int count = Integer.parseInt(args[3]);
        long interval = Long.parseLong(args[4]);
        long durationMillis = Long.parseLong(args[5]);
        if (count <= 8 || interval <= 0 || durationMillis <= 0) throw new IllegalArgumentException();
        CountDownLatch ready = new CountDownLatch(count);
        CountDownLatch release = new CountDownLatch(1);
        List<Thread> workers = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            final int index = i;
            Thread worker = new Thread(() -> {
                if (index < BUSY_THREADS) wallBusy(ready);
                else wallSleep(ready, release);
            }, "wall-population-" + i);
            workers.add(worker);
            worker.start();
        }
        ready.await();
        long elapsed = 0;
        try {
            profiler.execute("start,event=wall,interval=" + interval + ",filter,cstack=vm,jfr,file="
                    + recording + (nobatch ? ",nobatch" : ""));
            try {
                for (Thread worker : workers) profiler.addThread(worker);
                long begin = System.nanoTime();
                Thread.sleep(durationMillis);
                elapsed = System.nanoTime() - begin;
            } finally {
                profiler.stop();
            }
            Files.writeString(Path.of(recording + ".collapsed"), profiler.execute("collapsed,total"), StandardCharsets.UTF_8);
            System.out.println("WALL_POPULATION_CAPTURE mode=" + (nobatch ? "nobatch" : "batch")
                    + " threads=" + count + " busy=" + BUSY_THREADS + " intervalNs=" + interval + " elapsedNs=" + elapsed);
        } finally {
            running = false;
            release.countDown();
            for (Thread worker : workers) worker.join();
        }
    }
}
