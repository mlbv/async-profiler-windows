/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import jdk.jfr.consumer.RecordingFile;

public final class ReadReload {
    public static void main(String[] args) throws Exception {
        var count = 0;
        for (var event : RecordingFile.readAllEvents(Path.of(args[0]))) {
            if (!event.getEventType().getName().equals("jdk.ExecutionSample") || event.getStackTrace() == null) continue;
            var matched = false;
            for (var frame : event.getStackTrace().getFrames()) {
                var name = frame.getMethod().getName();
                matched |= name.contains(args[1]);
                if (!args[2].equals("-") && name.contains(args[2])) throw new AssertionError("Retired symbol was used: " + name);
            }
            if (matched) count++;
        }
        var expected = Integer.parseInt(args[3]);
        if (expected >= 0 ? count != expected : count == 0) throw new AssertionError("Expected matching stacks " + expected + ", got " + count);
        System.out.println("matched=" + count + " symbol=" + args[1]);
    }
}
