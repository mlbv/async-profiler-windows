/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
public final class FmaCompilerSnapshotSmoke {
    public static void main(String[] args) {
        System.load(args[0]);
        for (int i = 0; i < 2_000; ++i) EtwJavaSmoke.unprovenFmaTarget();
        String report = CompiledHandlerSnapshotSmoke.snapshot();
        System.out.print(report);
        if (!report.contains("UNSUPPORTED_CODE ")) {
            throw new AssertionError("Real level-4 FMA method snapshot unavailable");
        }
        System.out.println("FMA_COMPILER_SNAPSHOT_OK vm=" + System.getProperty("java.version"));
    }
}
