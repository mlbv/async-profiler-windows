/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import jdk.jfr.consumer.RecordingFile;

public final class ReadNativeApplication {
    public static void main(String[] args) throws Exception {
        var directory = Path.of(args[0]);
        ReadCounters.main(new String[]{directory.resolve("cycles.jfr").toString(), directory.resolve("cycles.collapsed").toString(), "cycles"});
        var stacks = 0;
        var user = 0;
        for (var event : RecordingFile.readAllEvents(directory.resolve("cycles.jfr"))) {
            var type = event.getEventType().getName();
            if (type.equals("jdk.JVMInformation")) throw new AssertionError("A JVM was reported in a native process");
            if (type.equals("jdk.ExecutionSample") && event.getStackTrace() != null
                    && event.getStackTrace().getFrames().stream().anyMatch(frame -> frame.getMethod().getName().contains("NativeCpuWork"))) stacks++;
            if (type.equals("profiler.UserEvent")) {
                if (!event.getString("type").equals("native.fixture")) throw new AssertionError("Wrong native user event");
                var data = event.getString("data");
                if (data.length() != 256) throw new AssertionError("Wrong native payload length");
                for (var i = 0; i < data.length(); ++i) if (data.charAt(i) != i) throw new AssertionError("Native payload changed");
                user++;
            }
        }
        var pointer = Long.parseUnsignedLong(args[1]);
        var allocations = 0;
        var frees = 0;
        for (var event : RecordingFile.readAllEvents(directory.resolve("memory.jfr"))) {
            if (event.getEventType().getName().equals("profiler.Malloc") && event.getLong("address") == pointer && event.getLong("size") == 131071) allocations++;
            if (event.getEventType().getName().equals("profiler.Free") && event.getLong("address") == pointer) frees++;
        }
        var locks = 0;
        for (var event : RecordingFile.readAllEvents(directory.resolve("locks.jfr"))) {
            if (!event.getEventType().getName().equals("profiler.NativeLock")) continue;
            if (event.getDuration().toMillis() >= 10 && event.getDuration().toMillis() < 1000) locks++;
        }
        if (stacks == 0 || user != 1 || allocations != 1 || frees != 1 || locks == 0) throw new AssertionError("Native app: stacks=" + stacks + " user=" + user + " allocations=" + allocations + " frees=" + frees + " locks=" + locks);
        System.out.println("nativeApp stacks=" + stacks + " exactAllocationPair=1 locks=" + locks + " JVM=absent");
    }
}
