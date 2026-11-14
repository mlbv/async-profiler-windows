/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */

package test.wall;

public class WallTransitions {
    private static volatile long counter;

    private static void burn(long nanos) {
        long deadline = System.nanoTime() + nanos;
        while (System.nanoTime() < deadline) {
            counter++;
        }
    }

    private static void firstSleep() throws InterruptedException {
        burn(100_000);
        Thread.sleep(300);
    }

    private static void secondSleep() throws InterruptedException {
        burn(100_000);
        Thread.sleep(300);
    }

    private static void thirdSleep() throws InterruptedException {
        burn(100_000);
        Thread.sleep(300);
    }

    public static void main(String[] args) throws Exception {
        long[] durations = new long[3];
        Thread worker = new Thread(() -> {
            try {
                // Establish a nonzero CPU-time baseline before the short wakeups.
                burn(50_000_000);
                long start = System.nanoTime();
                firstSleep();
                durations[0] = System.nanoTime() - start;
                start = System.nanoTime();
                secondSleep();
                durations[1] = System.nanoTime() - start;
                start = System.nanoTime();
                thirdSleep();
                durations[2] = System.nanoTime() - start;
            } catch (InterruptedException e) {
                throw new AssertionError(e);
            }
        }, "WallTransitions");
        worker.start();
        worker.join();
        for (long duration : durations) {
            System.out.println("WALL_PHASE_NS " + duration);
        }
    }
}
