/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import jdk.jfr.consumer.RecordingFile;

public final class ReadStartupProbe {
    public static void main(String[] args) throws Exception {
        var count = 0;
        for (var event : RecordingFile.readAllEvents(Path.of(args[0]))) {
            if (!event.getEventType().getName().equals("jdk.ExecutionSample") || event.getStackTrace() == null) continue;
            if (event.getStackTrace().getFrames().stream().anyMatch(frame ->
                    frame.getMethod().getType().getName().equals("NativeStartupFixture") && frame.getMethod().getName().equals("run"))) count++;
        }
        if (count != 100) throw new AssertionError("Expected 100 probes on the startup/main thread, got " + count);
        System.out.println("startupProbes=" + count);
    }
}
