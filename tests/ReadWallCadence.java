/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import jdk.jfr.consumer.RecordingFile;

public final class ReadWallCadence {
    public static void main(String[] args) throws Exception {
        var runnableTimes = new ArrayList<Long>();
        var sleepingTimes = new ArrayList<Long>();
        var sleepingSpan = 0L;
        var sleepingGaps = 0L;
        var runningSamples = 0L;
        var sleepingSamples = 0L;
        var runnableLast = Long.MIN_VALUE;
        for (var event : RecordingFile.readAllEvents(Path.of(args[0]))) {
            if (!event.getEventType().getName().equals("profiler.WallClockSample")) continue;
            var samples = event.getInt("samples");
            var thread = event.getThread("sampledThread").getJavaName();
            if (thread.equals("collector-main") && ReadCollectors.frame(event, "wallBusy")) {
                runningSamples += samples;
                var time = event.getStartTime();
                var nanos = time.getEpochSecond() * 1_000_000_000L + time.getNano();
                runnableTimes.add(nanos);
                runnableLast = Math.max(runnableLast, nanos + event.getDuration("timeSpan").toNanos());
            } else if (thread.equals("collector-sleeper") && ReadCollectors.frame(event, "wallSleep")) {
                sleepingSamples += samples;
                var time = event.getStartTime();
                sleepingTimes.add(time.getEpochSecond() * 1_000_000_000L + time.getNano());
                if (samples > 1) {
                    sleepingSpan += event.getDuration("timeSpan").toNanos();
                    sleepingGaps += samples - 1;
                }
            }
        }
        Collections.sort(runnableTimes);
        var deltas = new ArrayList<Long>();
        for (var i = 1; i < runnableTimes.size(); i++) deltas.add(runnableTimes.get(i) - runnableTimes.get(i - 1));
        Collections.sort(deltas);
        if (deltas.isEmpty()) throw new AssertionError("Insufficient per-thread cadence data");
        var median = deltas.get(deltas.size() / 2);
        var runnableMean = (runnableLast - runnableTimes.get(0)) / (runningSamples - 1);
        var requested = Long.parseLong(args[1]);
        var sleepingPeriod = sleepingGaps == 0 && sleepingTimes.size() > 1
                ? (sleepingTimes.get(sleepingTimes.size() - 1) - sleepingTimes.get(0)) / (sleepingTimes.size() - 1)
                : sleepingSpan / sleepingGaps;
        System.out.println("WALL_CADENCE requestedNs=" + requested + " runnableMedianNs=" + median
                + " runnableMeanNs=" + runnableMean + " sleepingPeriodNs=" + sleepingPeriod + " runningWeightNs=" + runningSamples * requested
                + " sleepingWeightNs=" + sleepingSamples * requested + " batchedSleepingGaps=" + sleepingGaps);
        if (args.length > 2) {
            if (sleepingGaps == 0 || runnableMean < requested / 2 || runnableMean > requested * 3 / 2
                    || sleepingPeriod > requested * 3 / 2 || runningSamples == runnableTimes.size() && median > requested * 3 / 2) {
                throw new AssertionError("Requested wall cadence not sustained");
            }
            if (runningSamples * requested < 800_000_000L || sleepingSamples * requested < 800_000_000L
                    || runningSamples * requested > 1_200_000_000L || sleepingSamples * requested > 1_200_000_000L) {
                throw new AssertionError("One-second runnable/sleeping thread-time weights are inaccurate");
            }
        }
    }
}
