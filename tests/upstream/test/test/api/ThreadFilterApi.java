/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

package test.api;

import one.profiler.AsyncProfiler;

public class ThreadFilterApi {
    private static volatile boolean started;
    private static volatile boolean running = true;
    private static volatile long counter;

    public static void main(String[] args) throws Exception {
        Thread included = new Thread(ThreadFilterApi::included);
        Thread excluded = new Thread(() -> {
            while (!started) Thread.yield();
            excluded();
        });
        included.start();
        excluded.start();

        AsyncProfiler profiler = AsyncProfiler.getInstance();
        profiler.execute("start,event=" + (args.length == 0 ? "wall" : args[0]) + ",filter");
        profiler.addThread(included);
        profiler.addThread(excluded);
        profiler.removeThread(excluded);
        started = true;
        Thread.sleep(1000);
        System.out.print(profiler.execute("dump,collapsed"));
        profiler.stop();

        running = false;
        included.join();
        excluded.join();
    }

    private static void included() {
        while (running) counter++;
    }

    private static void excluded() {
        while (running) counter++;
    }
}
