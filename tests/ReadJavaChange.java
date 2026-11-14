/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import java.util.ArrayList;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;

public final class ReadJavaChange {
    public static void main(String[] args) throws Exception {
        var versions = new int[3];
        var interpreted = 0;
        var compiled = 0;
        var partial = 0;
        var events = RecordingFile.readAllEvents(Path.of(args[0]));
        var intervals = new ArrayList<RecordedEvent>();
        for (var event : events) {
            if (event.getEventType().getName().equals("profiler.Span") && "class-change".equals(event.getString("tag"))) intervals.add(event);
        }
        var restarted = args.length > 2 && args[2].equals("restarted");
        if (intervals.size() != (restarted ? 3 : 4)) throw new AssertionError("Missing class-change span markers: " + intervals.size());
        var suppressed = 0;
        for (var event : events) {
            if (!event.getEventType().getName().equals("jdk.ExecutionSample")) continue;
            var changing = false;
            for (var interval : intervals) {
                changing |= event.getStartTime().isAfter(interval.getStartTime().plusMillis(3))
                        && event.getStartTime().isBefore(interval.getEndTime().minusMillis(3));
            }
            var uncertain = false;
            for (var frame : event.getStackTrace().getFrames()) {
                var method = frame.getMethod();
                if (method.getName().endsWith("unwind_incomplete")) { partial++; uncertain = true; }
                if (!method.getType().getName().equals("EtwJavaPayload") || !method.getName().equals("burn")) continue;
                if (changing) throw new AssertionError("Java metadata was trusted inside a class-change span");
                var line = frame.getLineNumber();
                if (line <= 0 || line >= 300 || frame.getBytecodeIndex() < 0) throw new AssertionError("Invalid changed Java location: " + frame);
                versions[line / 100]++;
                if (frame.getType().equals("Interpreted")) interpreted++;
                else if (frame.getType().equals("JIT compiled") || frame.getType().equals("C1 compiled") || frame.getType().equals("Inlined")) compiled++;
                else throw new AssertionError("Unexpected changed method frame type: " + frame.getType());
            }
            if (changing && uncertain) suppressed++;
        }
        for (var version = restarted ? 1 : 0; version < 3; version++) {
            if (versions[version] < 30) throw new AssertionError("Missing Java version " + version + ": " + versions[version]);
        }
        if (args[1].equals("interpreted") && interpreted == 0) throw new AssertionError("No changed interpreted methods");
        if (args[1].equals("compiled") && compiled == 0) throw new AssertionError("No changed compiled methods");
        if (partial == 0) throw new AssertionError("Class-change uncertainty was not visible");
        if (suppressed < 30) throw new AssertionError("Missing uncertain samples inside class-change spans: " + suppressed);
        System.out.println("JAVA_CHANGE_JFR_OK versions=" + java.util.Arrays.toString(versions)
                + " interpreted=" + interpreted + " compiled=" + compiled + " partial=" + partial + " suppressed=" + suppressed);
    }
}
