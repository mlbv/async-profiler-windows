/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

package one.profiler.test;

public class TestResult {
    private final TestStatus status;
    private final Throwable throwable;
    private final String reason;

    private TestResult(TestStatus status, Throwable throwable) {
        this(status, throwable, null);
    }

    private TestResult(TestStatus status, Throwable throwable, String reason) {
        if ((status == TestStatus.FAIL) ^ (throwable != null)) {
            throw new IllegalArgumentException();
        }

        this.status = status;
        this.throwable = throwable;
        this.reason = reason;
    }

    public TestStatus status() {
        return status;
    }

    public Throwable throwable() {
        return throwable;
    }

    public String reason() {
        return reason;
    }

    public static TestResult skipConfigMismatch() {
        return new TestResult(TestStatus.SKIP_CONFIG_MISMATCH, null);
    }

    public static TestResult skipDisabled() {
        return new TestResult(TestStatus.SKIP_DISABLED, null);
    }

    public static TestResult skipMissingJar() {
        return new TestResult(TestStatus.SKIP_MISSING_JAR, null);
    }

    public static TestResult skipEnvironment(String reason) {
        return new TestResult(TestStatus.SKIP_ENVIRONMENT, null, reason);
    }

    public static TestResult pass() {
        return new TestResult(TestStatus.PASS, null);
    }

    public static TestResult fail(Throwable t) {
        return new TestResult(TestStatus.FAIL, t);
    }
}
