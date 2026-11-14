/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.lang.management.ManagementFactory;
import jdk.jfr.Event;
import jdk.jfr.Name;

public final class Fixture {
    static volatile Object allocation;
    static volatile double result;
    static final Object lock = new Object();

    @Name("wrapper.Probe")
    static final class Probe extends Event { int iteration; }

    static void busy() {
        double sum = result;
        for (int i = 0; i < 100_000; i++) sum += Math.sqrt(i + sum % 19);
        result = sum;
    }

    public static void main(String[] args) throws Exception {
        Thread holder = new Thread(() -> {
            try {
                while (true) {
                    synchronized (lock) { Thread.sleep(35); }
                    Thread.sleep(5);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, "lock-holder");
        holder.setDaemon(true);
        holder.start();
        System.out.println("READY " + ManagementFactory.getRuntimeMXBean().getName().split("@")[0]);
        long end = System.nanoTime() + Long.parseLong(args[0]) * 1_000_000_000L;
        long nextGc = System.nanoTime();
        int iteration = 0;
        while (System.nanoTime() < end) {
            busy();
            for (int i = 0; i < 32; i++) allocation = new byte[8192];
            synchronized (lock) { result += 1; }
            Probe event = new Probe();
            event.iteration = iteration++;
            event.commit();
            if (System.nanoTime() >= nextGc) {
                System.gc();
                nextGc = System.nanoTime() + 1_000_000_000L;
            }
        }
    }
}
