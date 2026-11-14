/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import java.util.HashSet;
import jdk.jfr.consumer.RecordingFile;

public final class ReadLifecycleResume {
    public static void main(String[] args) throws Exception {
        var before = 0;
        var after = 0;
        var markers = 0;
        var tags = new HashSet<String>();
        try (var recording = new RecordingFile(Path.of(args[0]))) {
            while (recording.hasMoreEvents()) {
                var event = recording.readEvent();
                var type = event.getEventType().getName();
                if (type.equals("test.LifecyclePhase")) markers |= 1 << event.getInt("phase");
                if (type.equals("profiler.Span")) tags.add(event.getString("tag"));
                if (!type.equals("jdk.ExecutionSample")) continue;
                for (var frame : event.getStackTrace().getFrames()) {
                    var method = frame.getMethod();
                    if (!method.getType().getName().equals("LifecycleLimitSmoke")) continue;
                    if (method.getName().equals("beforeResume")) before++;
                    if (method.getName().equals("afterResume")) after++;
                }
            }
        }
        if (before < 10 || after < 10 || !tags.equals(java.util.Set.of("before-resume-𠮷", "after-resume-𠮷"))
                || (args[1].equals("sync") && markers != 6)) {
            throw new AssertionError("Missing resumed data: before=" + before + " after=" + after + " phaseBits=" + markers + " tags=" + tags);
        }
        System.out.println("RESUME_PHASES_OK before=" + before + " after=" + after + " phaseBits=" + markers);
    }
}
