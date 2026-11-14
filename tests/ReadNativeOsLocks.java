/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import java.util.Arrays;
import jdk.jfr.consumer.RecordingFile;

public final class ReadNativeOsLocks {
    public static void main(String[] args) throws Exception {
        var addresses = Arrays.stream(args[1].split(",")).mapToLong(Long::parseLong).toArray();
        var counts = new int[3];
        var stack = false;
        for (var event : RecordingFile.readAllEvents(Path.of(args[0]))) {
            if (!event.getEventType().getName().equals("profiler.NativeLock")) continue;
            for (var i = 0; i < addresses.length; i++) {
                if (event.getLong("address") != addresses[i]) continue;
                if (event.getDuration().toNanos() < 1_000_000 || event.getDuration().toNanos() > 5_000_000_000L) {
                    throw new AssertionError("Invalid OS lock duration " + event.getDuration());
                }
                if (counts[i]++ == 0) System.out.println(event);
                if (event.getThread() == null) throw new AssertionError("Missing native lock thread");
                stack |= event.getStackTrace() != null && event.getStackTrace().getFrames().stream()
                    .anyMatch(frame -> frame.getMethod().getType().getName().equals("NativeOsLockFixture"));
            }
        }
        System.out.println("lockCounts=" + Arrays.toString(counts));
        if (Arrays.stream(counts).anyMatch(count -> count == 0) || !stack) throw new AssertionError("Missing OS lock events or workload stacks");
    }
}
