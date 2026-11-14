/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
public final class CompiledHandlerSnapshotSmoke {
    private static volatile int sink;
    private static volatile double floating = 0.25;
    private static final class Expected extends RuntimeException {
        @Override public synchronized Throwable fillInStackTrace() { return this; }
    }
    private static final Expected EXPECTED = new Expected();
    private static final class Box { int value = 7; }
    private static final Box BOX = new Box();
    private static native String snapshot(Runnable workload, boolean witness, boolean implicit);
    private static native void checkpoint();
    static String snapshot() { return snapshot(null, false, false); }

    static void handlerLeaf(boolean fail) {
        if (fail) throw EXPECTED;
        sink ^= 1;
    }

    static void handlerTarget(boolean fail) {
        try { handlerLeaf(fail); }
        catch (Expected ignored) { checkpoint(); }
    }

    static void handlerCaller(boolean fail) { handlerTarget(fail); }
    static void handlerRoot(boolean fail) { handlerCaller(fail); }

    private static void warmCheckpoint() {
        for (int i = 0; i < 400_000; ++i) handlerRoot((i & 1) == 0);
    }

    static int leaf(int value) {
        if ((value & 15) == 0) throw EXPECTED;
        return value * 31 + 7;
    }

    static int throwing(int value) {
        try { return leaf(value); }
        catch (Expected ignored) { return -1; }
    }

    static int plain(int value) {
        return value * 31 + 7;
    }

    static int faulting(Box box) { return box.value; }
    static int dividing(int numerator, int divisor) { return numerator / divisor; }

    static void implicitCarrier(Box box) {
        try { sink ^= faulting(box); }
        catch (NullPointerException ignored) { checkpoint(); }
    }

    static void implicitCaller(Box box) { implicitCarrier(box); }
    static void implicitRoot(Box box) { implicitCaller(box); }

    private static void warmImplicitCheckpoint() {
        for (int i = 0; i < 20_000; ++i) {
            try { sink ^= faulting((i & 1) == 0 ? BOX : null); }
            catch (NullPointerException ignored) { sink ^= 1; }
        }
        for (int i = 0; i < 400_000; ++i) implicitRoot((i & 1) == 0 ? BOX : null);
    }

    static void scalar() {
        double value = floating;
        for (int i = 0; i < 100_000; ++i) value = value * 1.000000001 + 0.12345;
        floating = value;
    }

    private static void warmup() {
        for (int i = 0; i < 400_000; ++i) {
            sink ^= plain(i) ^ throwing(i) ^ faulting(BOX) ^ dividing(i, 3);
        }
        for (int i = 0; i < 2_000; ++i) scalar();
    }

    public static void main(String[] args) {
        System.load(args[0]);
        try {
            snapshot(() -> { throw EXPECTED; }, false, false);
            throw new AssertionError("Snapshot workload exception was lost");
        } catch (Expected actual) {
            if (actual != EXPECTED) throw new AssertionError("Snapshot workload exception changed", actual);
        }
        System.out.println("OBSERVER_WORKLOAD_EXCEPTION_OK");
        boolean implicit = Boolean.getBoolean("asprof.test.implicitWitness");
        boolean witness = implicit || Boolean.getBoolean("asprof.test.handlerWitness");
        String report = snapshot(() -> {
            warmup();
            if (witness) warmCheckpoint();
            if (implicit) warmImplicitCheckpoint();
        }, witness, implicit);
        System.out.print(report);
        if (!report.contains("SNAPSHOT_RUNTIME method=plain error=none")) {
            throw new AssertionError("Real plain compiled-method snapshot unavailable");
        }
        if (!report.contains("SNAPSHOT_RUNTIME method=throwing error=none")) {
            throw new AssertionError("Real throwing compiled-method snapshot unavailable");
        }
        if (witness && !report.contains("HANDLER_CONTEXT_WITNESS_OK")) {
            throw new AssertionError("Actual catch checkpoint witness unavailable");
        }
        if (implicit && !report.contains("IMPLICIT_FAULT_CONTEXT_WITNESS_OK")) {
            throw new AssertionError("Actual implicit-fault context witness unavailable");
        }
        System.out.println("COMPILED_HANDLER_SNAPSHOT_RUNTIME_OK vm=" + System.getProperty("java.version"));
    }
}
