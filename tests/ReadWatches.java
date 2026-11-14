/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import java.util.HashSet;
import jdk.jfr.consumer.RecordingFile;

public final class ReadWatches {
    public static void main(String[] args) throws Exception {
        var count = 0;
        var threads = new HashSet<Long>();
        var nativeFrame = false;
        var javaFrame = false;
        for (var event : RecordingFile.readAllEvents(Path.of(args[0]))) {
            if (!event.getEventType().getName().equals("jdk.ExecutionSample")) continue;
            count++;
            if (event.getLong("weight") != Long.parseLong(args[2])) throw new AssertionError("Wrong watchpoint weight");
            threads.add(event.getThread("sampledThread").getOSThreadId());
            if (event.getStackTrace() != null) for (var frame : event.getStackTrace().getFrames()) {
                nativeFrame |= frame.getMethod().getName().contains("watchWork");
                javaFrame |= frame.getMethod().getType().getName().equals("NativeWatchFixture");
            }
        }
        if (count != Integer.parseInt(args[1]) || threads.size() != 2 || !nativeFrame || !javaFrame) throw new AssertionError("Watchpoint: count=" + count + " threads=" + threads.size() + " native=" + nativeFrame + " java=" + javaFrame);
        System.out.println("watchSamples=" + count + " threads=2 native/java stacks=OK");
    }
}
