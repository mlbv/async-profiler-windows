/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import java.util.Arrays;
import jdk.jfr.consumer.RecordingFile;

public final class ReadNativeMemory {
    public static void main(String[] args) throws Exception {
        var pointers = Arrays.stream(args[1].split(",")).mapToLong(Long::parseLong).toArray();
        long[] sizes = {65537, 7063, 32771, 131071, 49157, 98317, 81929, 73739, 12289};
        if (args.length > 3) sizes = Arrays.stream(args[3].split(",")).mapToLong(Long::parseLong).toArray();
        var allocations = new int[pointers.length];
        var frees = new int[pointers.length];
        var active = new java.util.HashMap<Long, Integer>();
        var mode = args.length > 2 ? args[2] : "all";
        var expectedFreeCounts = args.length > 4 ? Arrays.stream(args[4].split(",")).mapToInt(Integer::parseInt).toArray() : null;
        var fixtureStack = false;
        var total = 0;
        var totalFrees = 0;
        var names = new java.util.TreeSet<String>();
        var events = RecordingFile.readAllEvents(Path.of(args[0]));
        events.sort(java.util.Comparator.comparing(jdk.jfr.consumer.RecordedEvent::getStartTime));
        {
            for (var event : events) {
                var name = event.getEventType().getName();
                names.add(name);
                if (!name.equals("profiler.Malloc") && !name.equals("profiler.Free")) continue;
                total++;
                var address = event.getLong("address");
                if (name.equals("profiler.Free")) {
                    totalFrees++;
                    var index = active.get(address);
                    if (index != null) frees[index]++;
                    continue;
                }
                active.remove(address);
                for (var i = 0; i < pointers.length; i++) {
                    if (address != pointers[i]) continue;
                    if (event.getLong("size") == sizes[i]) {
                        allocations[i]++;
                        active.put(address, i);
                        System.out.println(event);
                        var stack = event.getStackTrace();
                        fixtureStack |= stack != null && stack.getFrames().stream().anyMatch(frame ->
                            frame.getMethod().getName().contains("Java_NativeMemoryFixture_")
                            || frame.getMethod().getType().getName().equals("NativeMemoryFixture"));
                    }
                }
            }
        }
        System.out.println("Events=" + total + ", types=" + names);
        System.out.println("Allocations=" + Arrays.toString(allocations) + ", frees=" + Arrays.toString(frees));
        for (var i = 0; i < pointers.length; i++) {
            var expectedAllocations = mode.equals("sampled") ? 0 : 1;
            var expectedFrees = expectedFreeCounts != null ? expectedFreeCounts[i] : mode.equals("all") ? 1 : 0;
            if (allocations[i] != expectedAllocations || frees[i] != expectedFrees) {
                throw new AssertionError("Missing/duplicate exact allocation or free at index " + i);
            }
        }
        if (!mode.equals("sampled") && !fixtureStack) throw new AssertionError("No native or Java workload allocation stack");
        if (mode.equals("nofree") && totalFrees != 0) throw new AssertionError("nofree emitted free events");
        if (mode.equals("sampled") && totalFrees == 0) throw new AssertionError("Byte sampling suppressed free events");
    }
}
