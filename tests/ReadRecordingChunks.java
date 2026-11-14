/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import jdk.jfr.consumer.RecordingFile;

public final class ReadRecordingChunks {
    public static void main(String[] args) throws Exception {
        var nativeChunks = 0;
        var samples = 0;
        var total = 0L;
        for (var path : args) {
            var nativeChunk = false;
            var chunkSamples = 0;
            var chunkTotal = 0L;
            try (var recording = new RecordingFile(Path.of(path))) {
                while (recording.hasMoreEvents()) {
                    var event = recording.readEvent();
                    var type = event.getEventType().getName();
                    if (type.equals("jdk.ActiveRecording") && event.getString("name").startsWith("async-profiler ")) nativeChunk = true;
                    if (!type.equals("jdk.ExecutionSample")) continue;
                    chunkSamples++;
                    chunkTotal += event.getLong("weight");
                    for (var frame : event.getStackTrace().getFrames()) {
                        if (frame.getMethod().getName().equals("stale_jmethodID")) throw new AssertionError("Stale metadata across rollover");
                    }
                }
            }
            if (nativeChunk) {
                if (chunkSamples == 0 || chunkTotal <= 0) throw new AssertionError("Empty native chunk: " + path);
                nativeChunks++;
                samples += chunkSamples;
                total += chunkTotal;
            }
        }
        if (nativeChunks < 3) throw new AssertionError("Insufficient native rollover chunks: " + nativeChunks);
        System.out.println("NATIVE_CHUNKS_OK chunks=" + nativeChunks + " samples=" + samples + " total=" + total);
    }
}
