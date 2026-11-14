/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
package one.jfr.event;

import one.jfr.JfrReader;

/** Windows process counters with optional-field availability recorded explicitly. */
public final class WindowsProcessMetrics extends Event {
    public final int pid;
    public final int availableFields;
    public final String userSid;
    public final long pageFaults;
    public final long privateCommit;
    public final long privateWorkingSet;
    public final long sharedCommit;

    public WindowsProcessMetrics(JfrReader reader) {
        super(reader.getVarlong(), 0, 0);
        pid = reader.getVarint();
        availableFields = reader.getVarint();
        userSid = reader.getString();
        pageFaults = reader.getVarlong();
        privateCommit = reader.getVarlong();
        privateWorkingSet = reader.getVarlong();
        sharedCommit = reader.getVarlong();
    }
}
