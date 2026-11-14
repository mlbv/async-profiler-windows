/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import jdk.jfr.consumer.RecordingFile;

public final class ReadProbeArguments {
    public static void main(String[] args) throws Exception {
        var weights = new ArrayList<Long>();
        var javaStack = false;
        var nativeStack = false;
        var unit = "";
        var workers = args.length > 3 && args[3].equals("workers");
        var javaClass = args.length > 4 ? args[4] : "NativeProbeArguments";
        for (var event : RecordingFile.readAllEvents(Path.of(args[0]))) {
            if (event.getEventType().getName().equals("jdk.ActiveSetting") && event.getString("name").equals("counterUnit")) unit = event.getString("value");
            if (!event.getEventType().getName().equals("jdk.ExecutionSample")) continue;
            weights.add(event.getLong("weight"));
            if (event.getThread("sampledThread") == null) throw new AssertionError("Missing probe thread");
            if (event.getStackTrace() != null) for (var frame : event.getStackTrace().getFrames()) {
                javaStack |= frame.getMethod().getType().getName().equals(javaClass);
                nativeStack |= frame.getMethod().getName().contains("ProbeArguments")
                    || frame.getMethod().getName().contains("nativeProbeArguments.dll+0x");
            }
        }
        var expected = args[1].isEmpty() ? java.util.List.<Long>of() : Arrays.stream(args[1].split(",")).map(Long::valueOf).toList();
        var frames = weights.isEmpty() ? !javaStack && !nativeStack : nativeStack && (workers ? !javaStack : javaStack);
        if (!weights.equals(expected) || !frames || !unit.equals(args[2])) {
            throw new AssertionError("weights=" + weights + " expected=" + expected + " java=" + javaStack + " native=" + nativeStack + " unit=" + unit);
        }
        System.out.println("PROBE_ARGUMENTS_OK samples=" + weights.size() + " weight=" + weights.stream().mapToLong(Long::longValue).sum());
    }
}
