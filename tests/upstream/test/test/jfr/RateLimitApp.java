/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

package test.jfr;

import one.profiler.Span;

/**
 * Generates a flood of JFR events of three different categories.
 */
public class RateLimitApp {

    private static volatile Object sink;
    private static volatile long counter;

    private static void burnCpu() {
        long result = 0;
        while (true) {
            for (int i = 0; i < 10_000; i++) {
                result += i * 31 + (result >> 1);
            }
            counter = result;
        }
    }

    private static void allocate() {
        while (true) {
            sink = new byte[4096];
        }
    }

    private static void emitSpans() {
        while (true) {
            long span = Span.start();
            counter++;
            Span.end(span, "flood");
        }
    }

    public static void main(String[] args) {
        // The runner owns this process's lifetime: Windows attach and symbol loading can exceed
        // the two seconds of startup slack in upstream's six-second workload.
        Thread[] threads = {
            new Thread(RateLimitApp::burnCpu),
            new Thread(RateLimitApp::burnCpu),
            new Thread(RateLimitApp::allocate),
            new Thread(RateLimitApp::emitSpans),
        };
        for (Thread thread : threads) {
            thread.start();
        }
    }
}
