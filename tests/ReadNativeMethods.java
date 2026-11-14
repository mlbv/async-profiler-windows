/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import jdk.jfr.consumer.RecordingFile;

public final class ReadNativeMethods {
    public static void main(String[] args) throws Exception {
        var count = 0;
        try (var file = new RecordingFile(Path.of(args[0]))) {
            while (file.hasMoreEvents()) {
                var event = file.readEvent();
                if (!event.getEventType().getName().equals("jdk.ExecutionSample")) continue;
                var trace = event.getStackTrace();
                if (trace == null || trace.getFrames().isEmpty()) throw new AssertionError("Missing method-entry stack");
                var first = trace.getFrames().get(0).getMethod();
                if (!first.getType().getName().equals("NativeMethodFixture") || !first.getName().equals("work")) {
                    throw new AssertionError("Unexpected method-entry frame: " + first.getType().getName() + "." + first.getName());
                }
                if (count++ == 0) System.out.println(event);
            }
        }
        var expected = Integer.parseInt(args[1]);
        if (count != expected) throw new AssertionError("Expected " + expected + " method entries, got " + count);
        System.out.println("methodEntries=" + count);
    }
}
