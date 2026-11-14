/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

package test.smoke;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadLocalRandom;

public class Alloc implements Runnable {
    static volatile Object sink;
    private static final CountDownLatch ready = new CountDownLatch(2);

    public static void main(String[] args) throws Exception {
        new Thread(new Alloc(), "AllocThread-1").start();
        new Thread(new Alloc(), "AllocThread-2").start();
        if (args.length != 0) {
            ready.await();
            Files.write(Paths.get(args[0]), new byte[]{1});
        }
    }

    @Override
    public void run() {
        Random random = ThreadLocalRandom.current();
        allocate(random);
        ready.countDown();
        while (true) {
            allocate(random);
        }
    }

    private static void allocate(Random random) {
        if (random.nextBoolean()) {
            sink = new int[128 * 1000];
        } else {
            sink = new Integer[128 * 1000];
        }
    }
}
