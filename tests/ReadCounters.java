/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Files;
import java.nio.file.Paths;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordedFrame;
import jdk.jfr.consumer.RecordingFile;

public final class ReadCounters {
    public static void main(String[] args) throws Exception {
        long total = 0;
        int samples = 0;
        String unit = "";
        long period = args.length > 3 ? Long.parseLong(args[3]) : 0;
        int namedStacks = 0;
        for (RecordedEvent event : RecordingFile.readAllEvents(Paths.get(args[0]))) {
            if (event.getEventType().getName().equals("jdk.ActiveSetting") && event.getString("name").equals("counterUnit")) unit = event.getString("value");
            if (!event.getEventType().getName().equals("jdk.ExecutionSample")) continue;
            long weight = event.getLong("weight");
            if (weight <= 0) throw new AssertionError("Nonpositive counter weight");
            if (period != 0 && weight != period) throw new AssertionError("Wrong event period weight: " + weight + " expected=" + period);
            if (args.length > 4) {
                boolean workload = false;
                boolean caller = args.length < 6;
                if (event.getStackTrace() != null) {
                    for (RecordedFrame frame : event.getStackTrace().getFrames()) {
                        String name = frame.getMethod().getName();
                        workload |= name.contains(args[4]);
                        caller |= args.length > 5 && name.contains(args[5]);
                    }
                }
                if (workload && caller) namedStacks++;
            }
            total += weight;
            samples++;
        }
        long collapsed = 0;
        for (String line : Files.readAllLines(Paths.get(args[1]))) {
            if (!line.trim().isEmpty()) collapsed += Long.parseLong(line.substring(line.lastIndexOf(' ') + 1));
        }
        if (samples == 0 || total != collapsed || !unit.equals(args[2])) throw new AssertionError("Counter mismatch: JFR=" + total + " collapsed=" + collapsed + " unit=" + unit);
        if (args.length > 4 && namedStacks == 0) throw new AssertionError("No sample contains the named workload and caller");
        System.out.println("weightedSamples=" + samples + " total=" + total + " unit=" + unit + " namedStacks=" + namedStacks);
    }
}
