/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import java.util.TreeMap;
import jdk.jfr.consumer.RecordingFile;

public final class ReadRecording {
    public static void main(String[] args) throws Exception {
        var counts = new TreeMap<String, Long>();
        var fixtureStack = false;
        try (var file = new RecordingFile(Path.of(args[0]))) {
            while (file.hasMoreEvents()) {
                var event = file.readEvent();
                counts.merge(event.getEventType().getName(), 1L, Long::sum);
                if (args.length > 2 && (event.getEventType().getName().equals("jdk.ExecutionSample")
                        || event.getEventType().getName().equals("wrapper.Probe"))) {
                    var time = event.getStartTime().toEpochMilli();
                    if (time < Long.parseLong(args[1]) || time > Long.parseLong(args[2])) {
                        throw new AssertionError("Native/JVM timestamp is outside the recording window: " + event.getEventType().getName()
                                + " " + event.getStartTime());
                    }
                }
                var stack = event.getStackTrace();
                if (stack != null && event.getEventType().getName().equals("jdk.ExecutionSample")) {
                    fixtureStack |= stack.getFrames().stream().anyMatch(frame -> frame.getMethod().getType().getName().equals("Fixture"));
                }
            }
        }
        for (var entry : counts.entrySet()) System.out.println(entry.getKey() + "=" + entry.getValue());
        System.out.println("fixtureStack=" + fixtureStack);
    }
}
