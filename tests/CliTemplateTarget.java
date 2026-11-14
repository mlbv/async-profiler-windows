/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
/** Keeps native CPU sampling deterministic while the shared fixture emits JVM events. */
public final class CliTemplateTarget {
    public static void main(String[] args) throws Exception {
        var worker = new Thread(() -> {
            while (true) Fixture.busy();
        }, "template-cpu");
        worker.setDaemon(true);
        worker.start();
        Fixture.main(args);
    }
}
