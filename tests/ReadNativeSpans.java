/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import java.util.HashSet;
import jdk.jfr.consumer.RecordingFile;

public final class ReadNativeSpans {
    public static void main(String[] args) throws Exception {
        var tags = new HashSet<String>();
        var count = 0;
        for (var event : RecordingFile.readAllEvents(Path.of(args[0]))) {
            if (!event.getEventType().getName().equals("profiler.Span")) continue;
            count++;
            var tag = event.getString("tag");
            if (!tags.add(tag)) throw new AssertionError("Duplicate span tag: " + tag);
            if (event.getThread() == null || event.getStartTime().getEpochSecond() < 1_000_000_000L) throw new AssertionError("Wrong span clock/thread");
            if (args.length > 2) {
                var time = event.getStartTime().toEpochMilli();
                if (time < Long.parseLong(args[1]) || time > Long.parseLong(args[2])) {
                    throw new AssertionError("Span timestamp is outside the recording window: " + event.getStartTime());
                }
            }
            if (tag != null && tag.startsWith("sampled.") && event.getDuration().toNanos() < 1_000_000) throw new AssertionError("Missing span duration");
        }
        for (var i = 0; i < 10; i++) if (!tags.contains("sampled." + i)) throw new AssertionError("Missing sampled span " + i);
        for (var i = 0; i < 64; i++) if (!tags.contains("large." + i + ":" + "x".repeat(4096))) throw new AssertionError("Missing long tag " + i);
        if (count != 78 || !tags.contains("isolated") || !tags.contains("") || !tags.contains(null) || !tags.contains("zero\0emoji\ud83d\ude42")) throw new AssertionError("Unexpected span count or altered tags: " + count);
        System.out.println("nativeSpans=" + count + " tagBytes>262144");
    }
}
