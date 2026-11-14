/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
public final class EtwJavaPayload {
    static volatile long result;
    public static void burn() {
        var end = System.nanoTime() + 180_000_000L;
        var value = result;
        while (System.nanoTime() < end) {
            for (var i = 0; i < 10_000; i++) value = Long.rotateLeft(value ^ i, 7) * 0x100000001b3L;
        }
        result = value;
    }
}
