/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import jdk.jfr.consumer.RecordingFile;

public final class ReadLifecycleBounds {
    public static void main(String[] args) throws Exception {
        var first = Long.MAX_VALUE;
        var last = Long.MIN_VALUE;
        try (var recording = new RecordingFile(Path.of(args[0]))) {
            while (recording.hasMoreEvents()) {
                var event = recording.readEvent();
                if (!event.getEventType().getName().equals("jdk.ExecutionSample")) continue;
                var time = event.getStartTime().toEpochMilli();
                first = Math.min(first, time);
                last = Math.max(last, time);
            }
        }
        if (last == Long.MIN_VALUE) throw new AssertionError("Missing execution samples");
        if (args.length > 1 && last > Long.parseLong(args[1]) + 500) {
            throw new AssertionError("Samples exceed the requested deadline: last=" + last + " deadline=" + args[1]);
        }
        System.out.println("SAMPLE_BOUNDS_OK firstMs=" + first + " lastMs=" + last + " spanMs=" + (last - first));
    }
}
