/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;

// Checks recordings of native applications started through asprof-helper --preload.
public final class ReadPreload {
    public static void main(String[] args) throws Exception {
        var events = RecordingFile.readAllEvents(Path.of(args[1]));
        if (events.stream().anyMatch(event -> event.getEventType().getName().equals("jdk.JVMInformation"))) {
            throw new AssertionError("A JVM was reported in a native process");
        }
        switch (args[0]) {
            case "cpu" -> {
                var samples = events.stream().filter(event -> event.getEventType().getName().equals("jdk.ExecutionSample")
                        && calls(event, "PreloadCpuWork")).count();
                if (samples == 0) throw new AssertionError("No PreloadCpuWork samples");
                System.out.println("preload cpu samples=" + samples);
            }
            case "malloc" -> {
                // Upstream's assertNoLeaks over the requested sizes: each is allocated once and freed.
                var sizes = new HashMap<Long, Long>();
                for (var i = 2; i < args.length; i++) sizes.put(Long.parseLong(args[i]), 0L);
                var live = new HashMap<Long, Long>();
                var frees = 0;
                for (var event : events) {
                    var type = event.getEventType().getName();
                    if (type.equals("profiler.Malloc") && sizes.containsKey(event.getLong("size"))) {
                        sizes.merge(event.getLong("size"), 1L, Long::sum);
                        live.put(event.getLong("address"), event.getLong("size"));
                    } else if (type.equals("profiler.Free") && live.remove(event.getLong("address")) != null) {
                        frees++;
                    }
                }
                if (sizes.values().stream().anyMatch(count -> count != 1) || !live.isEmpty()) {
                    throw new AssertionError("Allocations by size " + sizes + ", unfreed " + live);
                }
                System.out.println("preload malloc sizes=" + sizes.keySet() + " frees=" + frees);
            }
            case "java" -> {
                // A JVM started after preloading is profiled as a native process, like upstream's ldpreload case.
                var allocations = events.stream().filter(event -> event.getEventType().getName().equals("profiler.Malloc")
                        && calls(event, "JNI_CreateJavaVM")).count();
                if (allocations == 0) throw new AssertionError("No JVM creation allocations");
                System.out.println("preload JVM creation allocations=" + allocations);
            }
            case "locks" -> {
                var counts = new HashMap<String, Long>(Map.of("mutexContentionThread", 0L, "rwlockReaderThread", 0L, "rwlockWriterThread", 0L));
                for (var event : events) {
                    if (!event.getEventType().getName().equals("profiler.NativeLock")) continue;
                    for (var name : List.copyOf(counts.keySet())) if (calls(event, name)) counts.merge(name, 1L, Long::sum);
                }
                if (counts.values().contains(0L)) throw new AssertionError("Native lock events by caller " + counts);
                System.out.println("preload native locks " + counts);
            }
            default -> throw new IllegalArgumentException(args[0]);
        }
    }

    private static boolean calls(RecordedEvent event, String name) {
        var trace = event.getStackTrace();
        return trace != null && trace.getFrames().stream().anyMatch(frame -> frame.getMethod().getName().equals(name));
    }
}
