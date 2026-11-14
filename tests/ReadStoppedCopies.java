/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import jdk.jfr.consumer.RecordingFile;

/** Exposes the native sample timestamps and weights for exact stopped-copy comparison. */
public final class ReadStoppedCopies {
    public static void main(String[] args) throws Exception {
        var samples = new ArrayList<String>();
        for (var event : RecordingFile.readAllEvents(Path.of(args[0]))) {
            if (event.getEventType().getName().equals("jdk.ExecutionSample") && event.hasField("weight")) {
                samples.add(event.getStartTime() + " " + event.getLong("weight"));
            }
        }
        if (samples.isEmpty()) throw new AssertionError("No weighted native samples");
        Collections.sort(samples);
        for (var sample : samples) System.out.println(sample);
    }
}
