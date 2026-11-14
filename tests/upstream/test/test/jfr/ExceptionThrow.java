/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

package test.jfr;

public class ExceptionThrow {
    static final String MESSAGE = "jfrsync-event-setting";

    private static void throwException() {
        try {
            throw new Exception(MESSAGE);
        } catch (Exception ignored) {
        }
    }

    public static void main(String[] args) {
        throwException();
    }
}
