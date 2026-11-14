/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.util.concurrent.locks.ReentrantLock;

public final class NativeLockFixture {
    static final Object monitor = new Object();
    static final ReentrantLock concurrent = new ReentrantLock();
    static volatile long iterations;

    public static void main(String[] args) throws Exception {
        var holder = new Thread(() -> {
            try {
                while (true) {
                    synchronized (monitor) { Thread.sleep(15); }
                    Thread.sleep(2);
                }
            } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }, "monitor-holder");
        var parker = new Thread(() -> {
            try {
                while (true) {
                    concurrent.lock();
                    try { Thread.sleep(20); }
                    finally { concurrent.unlock(); }
                    Thread.sleep(2);
                }
            } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }, "concurrent-holder");
        holder.setDaemon(true);
        parker.setDaemon(true);
        holder.start();
        parker.start();
        var commands = new Thread(() -> {
            try {
                var input = new java.io.BufferedReader(new java.io.InputStreamReader(System.in));
                if (!"block".equals(input.readLine())) return;
                var held = new ReentrantLock();
                held.lock();
                var waiter = new Thread(held::lock, "indefinitely-parked");
                waiter.setDaemon(true);
                waiter.start();
                var deadline = System.nanoTime() + 5_000_000_000L;
                while (waiter.getState() != Thread.State.WAITING && System.nanoTime() < deadline) Thread.sleep(1);
                if (waiter.getState() != Thread.State.WAITING) throw new AssertionError("Waiter did not park");
                System.out.println("BLOCKED");
                // This daemon exits while retaining the lock, keeping the waiter parked.
            } catch (Exception e) { throw new RuntimeException(e); }
        }, "commands");
        commands.setDaemon(true);
        commands.start();
        System.out.println("READY " + ProcessHandle.current().pid());
        var end = System.nanoTime() + Long.parseLong(args[0]) * 1_000_000_000L;
        while (System.nanoTime() < end) {
            synchronized (monitor) { iterations++; }
            concurrent.lock();
            try { iterations++; }
            finally { concurrent.unlock(); }
            Thread.sleep(1);
        }
    }
}
