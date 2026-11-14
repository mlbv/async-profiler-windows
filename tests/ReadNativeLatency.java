/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import jdk.jfr.consumer.RecordingFile;

public final class ReadNativeLatency {
    public static void main(String[] args) throws Exception {
        var count = 0;
        var minimum = Long.parseLong(args[2]);
        try (var file = new RecordingFile(Path.of(args[0]))) {
            while (file.hasMoreEvents()) {
                var event = file.readEvent();
                if (!event.getEventType().getName().equals("jdk.MethodTrace")) continue;
                var duration = event.getDuration().toNanos();
                if (duration < minimum || duration > 1_000_000_000L) throw new AssertionError("Invalid latency " + duration);
                if (event.getThread() == null) throw new AssertionError("Missing event thread");
                var trace = event.getStackTrace();
                if (trace == null || trace.getFrames().isEmpty()) throw new AssertionError("Missing latency stack");
                var method = trace.getFrames().get(0).getMethod();
                if (!method.getType().getName().equals("NativeLatencyFixture")
                        || !(method.getName().equals("work") || method.getName().equals("second"))) {
                    throw new AssertionError("Unexpected latency frame " + method.getType().getName() + "." + method.getName());
                }
                if (count++ == 0) System.out.println(event);
            }
        }
        if (count != Integer.parseInt(args[1])) throw new AssertionError("Expected " + args[1] + " latency events, got " + count);
        System.out.println("latencyEvents=" + count);
    }
}
