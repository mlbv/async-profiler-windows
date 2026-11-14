/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.ByteBuffer;
import jdk.jfr.consumer.RecordingFile;

public final class ReadLegacyProfile {
    public static void main(String[] args) throws Exception {
        var chains = 0;
        var lines = 0;
        var spans = 0;
        var pcChains = 0;
        var mixedChains = 0;
        var features = args.length > 2 ? args[2] : "";
        byte[] header;
        try (var stream = Files.newInputStream(Path.of(args[0]))) { header = stream.readNBytes(68); }
        var bytes = ByteBuffer.wrap(header);
        var firstMillis = bytes.getLong(32) / 1_000_000;
        var lastMillis = firstMillis + bytes.getLong(40) / 1_000_000;
        for (var event : RecordingFile.readAllEvents(Path.of(args[0]))) {
            if (event.getEventType().getName().equals("profiler.Span") || event.getEventType().getName().equals("jdk.ExecutionSample")) {
                if (event.getStartTime().toEpochMilli() < firstMillis - 500 || event.getEndTime().toEpochMilli() > lastMillis + 500) {
                    throw new AssertionError("Legacy sample/SDK timestamp is outside its recording: " + event.getStartTime());
                }
            }
            if (event.getEventType().getName().equals("profiler.Span")) {
                if (!("legacy." + args[1] + ".\ud83d\ude42").equals(event.getString("tag"))) throw new AssertionError("Legacy span tag changed");
                var duration = event.getDuration().toNanos();
                if (duration < 1_500_000_000L || duration > 5_000_000_000L) throw new AssertionError("Legacy SDK clock is incorrect: " + duration);
                spans++;
            }
            if (!event.getEventType().getName().equals("jdk.ExecutionSample")) continue;
            var leaf = false;
            var outer = false;
            var nativeRoot = false;
            for (var frame : event.getStackTrace().getFrames()) {
                var method = frame.getMethod();
                nativeRoot |= method.getName().equals("RtlUserThreadStart");
                if (!method.getType().getName().equals("LegacyProfilerSmoke")) continue;
                leaf |= method.getName().equals("燃烧𠮷");
                outer |= method.getName().equals("outer");
                if (frame.getLineNumber() > 0 && frame.getBytecodeIndex() >= 0) lines++;
            }
            if (leaf && outer) {
                chains++;
                if (event.getStackTrace().getFrames().get(0).getMethod().getName().matches("[0-9a-fA-F]{16}")) pcChains++;
                if (nativeRoot) mixedChains++;
            }
        }
        if (chains < 10 || lines == 0 || spans != 1) throw new AssertionError("Legacy profile incomplete: chains=" + chains + " lines=" + lines + " spans=" + spans);
        if (features.contains("pcaddr") && pcChains < 10) throw new AssertionError("Exact PC feature did not prefix Java traces: " + pcChains);
        if (features.contains("mixed") && mixedChains < 10) throw new AssertionError("Mixed feature did not retain Java/native callers: " + mixedChains);
        System.out.println("LEGACY_JFR_OK chains=" + chains + " lines=" + lines + " spans=" + spans + " pcChains=" + pcChains + " mixedChains=" + mixedChains);
    }
}
