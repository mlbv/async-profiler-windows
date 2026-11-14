/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import java.util.ArrayList;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;

public final class ReadWindows {
    public static void main(String[] args) throws Exception {
        var windows = new ArrayList<RecordedEvent>();
        var samples = new ArrayList<RecordedEvent>();
        var inside = 0;
        var outside = 0;
        var targetSamples = 0;
        var targetMethod = args.length > 4 ? args[4] : "";
        for (var event : RecordingFile.readAllEvents(Path.of(args[0]))) {
            if (event.getEventType().getName().equals("profiler.Window")) {
                if (event.getDuration().isNegative() || event.getDuration().toSeconds() >= 10 || event.getThread() == null) throw new AssertionError("Invalid window: " + event);
                windows.add(event);
            }
            if (event.getEventType().getName().equals("jdk.ExecutionSample") || event.getEventType().getName().equals("profiler.WallClockSample")) {
                samples.add(event);
                var target = false;
                if (event.getStackTrace() != null) for (var frame : event.getStackTrace().getFrames()) {
                    var name = frame.getMethod().getName();
                    if (name.contains("WindowInsideBusy")) inside++;
                    if (name.contains("WindowOutsideBusy")) outside++;
                    target |= !targetMethod.isEmpty() && name.equals(targetMethod);
                }
                if (target) targetSamples++;
            }
        }
        var expected = Integer.parseInt(args[1]);
        if (expected >= 0 && samples.size() != expected || expected == -1 && (samples.isEmpty() || inside == 0 || outside != 0)
                || expected == -2 && samples.isEmpty() || expected == -3 && (inside == 0 || outside == 0)) {
            throw new AssertionError("Wrong samples: " + samples.size() + " inside=" + inside + " outside=" + outside);
        }
        var expectedWindows = Integer.parseInt(args[2]);
        if (expectedWindows >= 0 && windows.size() != expectedWindows || expectedWindows < 0 && windows.isEmpty()) throw new AssertionError("Wrong window count: " + windows.size());
        var outsideWindows = args[3].equals("bounded") || args[3].equals("outside") ? 0 : -1;
        if (outsideWindows >= 0) for (var sample : samples) {
            var time = sample.getStartTime();
            var end = sample.hasField("timeSpan") ? time.plus(sample.getDuration("timeSpan")) : time;
            if (windows.stream().noneMatch(window -> !time.isBefore(window.getStartTime()) && !end.isAfter(window.getEndTime()))) {
                outsideWindows++;
                if (args[3].equals("bounded")) throw new AssertionError("Sample is outside every window: " + sample);
            }
        }
        if (args[3].equals("outside") && outsideWindows == 0) throw new AssertionError("Expected nostop samples outside safepoint windows");
        if (!targetMethod.isEmpty() && targetSamples < Integer.parseInt(args[5])) throw new AssertionError("Missing " + targetMethod + " workload samples: " + targetSamples);
        System.out.println("windows=" + windows.size() + " samples=" + samples.size() + " inside=" + inside + " outside=" + outside
                + " outsideWindows=" + outsideWindows + " targetSamples=" + targetSamples);
    }
}
