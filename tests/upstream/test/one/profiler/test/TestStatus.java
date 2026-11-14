/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

package one.profiler.test;

public enum TestStatus {
    PASS,
    FAIL,
    SKIP_DISABLED,
    SKIP_CONFIG_MISMATCH,
    SKIP_MISSING_JAR,
    SKIP_ENVIRONMENT,
}
