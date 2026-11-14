/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import java.util.HashSet;
import jdk.jfr.consumer.RecordingFile;

public class ReadTracepoint {
    public static void main(String[] args) throws Exception {
        int samples = 0, chains = 0, roots = 0;
        boolean javaOnly = args[1].equals("java-only");
        int interval = args[1].equals("interval") ? 7 : 1;
        try (var recording = new RecordingFile(Path.of(args[0]))) {
            while (recording.hasMoreEvents()) {
                var event = recording.readEvent();
                if (!event.getEventType().getName().equals("jdk.ExecutionSample")) continue;
                samples++;
                var names = new HashSet<String>();
                boolean cpu = false;
                for (var frame : event.getStackTrace().getFrames()) {
                    var method = frame.getMethod();
                    var name = method.getName();
                    if (method.getType().getName().equals("TracepointSmoke")) names.add(name);
                    if (name.equals("RtlUserThreadStart")) roots++;
                    if (name.startsWith("CPU-")) cpu = true;
                    if (javaOnly && !name.startsWith("CPU-") && (frame.getType().equals("Native") || frame.getType().equals("Kernel"))) {
                        throw new AssertionError("Native frame retained with cstack=no: " + name);
                    }
                    if (name.contains("etw_") && name.contains("incomplete")) throw new AssertionError("Incomplete tracepoint stack: " + name);
                }
                if (names.containsAll(java.util.Set.of("燃烧𠮷", "middle", "outer", "main"))) chains++;
                if (!cpu) throw new AssertionError("Captured processor index was lost");
            }
        }
        int expected = args[1].startsWith("kernel-") ? 1 : 1024 / interval;
        if (samples != expected || chains != samples) throw new AssertionError("Event/Java caller count mismatch: " + samples + "/" + chains);
        if (!javaOnly && roots * 100 < samples * 95) throw new AssertionError("Native roots incomplete: " + roots + "/" + samples);
        System.out.println("TRACEPOINT_READER_PASS samples=" + samples + " chains=" + chains + " roots=" + roots);
    }
}
