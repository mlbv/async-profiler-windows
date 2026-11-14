/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import java.util.HashSet;
import jdk.jfr.consumer.RecordingFile;

public final class ReadRecordingLimits {
    public static void main(String[] args) throws Exception {
        var expected = Integer.parseInt(args[0]);
        var seen = new HashSet<Integer>();
        var nativeChunks = 0;
        var populatedChunks = 0;
        for (var i = 1; i < args.length; i++) {
            var nativeChunk = false;
            var events = 0;
            try (var recording = new RecordingFile(Path.of(args[i]))) {
                while (recording.hasMoreEvents()) {
                    var event = recording.readEvent();
                    var type = event.getEventType().getName();
                    if (type.equals("jdk.ActiveRecording") && event.getString("name").startsWith("async-profiler ")) nativeChunk = true;
                    if (!type.equals("profiler.UserEvent")) continue;
                    var data = event.getString("data");
                    if (data.length() != 2048) throw new AssertionError("User event payload changed length: " + data.length());
                    var sequence = Integer.parseInt(data.substring(0, 8), 16);
                    if (sequence < 0 || sequence >= expected || !seen.add(sequence)) {
                        throw new AssertionError("Lost or duplicated rollover event: " + sequence);
                    }
                    events++;
                }
            }
            if (nativeChunk) nativeChunks++;
            if (events != 0) populatedChunks++;
        }
        if (nativeChunks < 3 || populatedChunks < 2 || seen.size() != expected) {
            throw new AssertionError("Size rollover mismatch: chunks=" + nativeChunks + " populated=" + populatedChunks + " events=" + seen.size());
        }
        System.out.println("SIZE_ROLLOVER_OK chunks=" + nativeChunks + " populated=" + populatedChunks + " events=" + seen.size());
    }
}
