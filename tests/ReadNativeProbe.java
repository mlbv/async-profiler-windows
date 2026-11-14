/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import java.util.HashSet;
import jdk.jfr.consumer.RecordingFile;

public final class ReadNativeProbe {
    public static void main(String[] args) throws Exception {
        var count = 0;
        var threads = new HashSet<Long>();
        var nativeStack = false;
        var javaStack = false;
        for (var event : RecordingFile.readAllEvents(Path.of(args[0]))) {
            if (!event.getEventType().getName().equals("jdk.ExecutionSample")) continue;
            count++;
            var thread = event.getThread("sampledThread");
            if (thread == null) throw new AssertionError("Missing probe thread");
            threads.add(thread.getOSThreadId());
            if (event.getStackTrace() == null) continue;
            for (var frame : event.getStackTrace().getFrames()) {
                var name = frame.getMethod().getName();
                nativeStack |= name.contains("ProbeWork") || name.contains("nativeMemoryFixture.dll+0x");
                javaStack |= frame.getMethod().getType().getName().equals("NativeProbeFixture");
            }
        }
        System.out.println("samples=" + count + " threads=" + threads.size() + " nativeStack=" + nativeStack + " javaStack=" + javaStack);
        var expected = Integer.parseInt(args[1]);
        if (expected == 0) {
            if (count != 0 || !threads.isEmpty() || nativeStack || javaStack) throw new AssertionError("Expected no per-thread counter overflow");
            return;
        }
        var workers = args.length > 2 && args[2].equals("workers");
        if (count != expected || (workers ? threads.size() < 2 : threads.size() != 2) || !nativeStack || !workers && !javaStack) {
            throw new AssertionError("Missing exact native probe counts, new-thread coverage, or workload stacks");
        }
    }
}
