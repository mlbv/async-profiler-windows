/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;

public final class ReadWallPopulation {
    static final class Samples {
        long count, records, first = Long.MAX_VALUE, last = Long.MIN_VALUE, batched;
        long expectedFrames, expectedState;
        final ArrayList<Long> times = new ArrayList<>();
    }

    static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }

    static boolean frame(RecordedEvent event, String method) {
        if (event.getStackTrace() == null) return false;
        for (var frame : event.getStackTrace().getFrames()) {
            require(!frame.getMethod().getName().equals("stale_jmethodID"), "Stale wall method metadata");
            if (frame.getMethod().getType().getName().equals("WallPopulation") && frame.getMethod().getName().equals(method))
                return true;
        }
        return false;
    }

    public static void main(String[] args) throws Exception {
        Path recording = Path.of(args[0]);
        boolean nobatch = Boolean.parseBoolean(args[1]);
        int threads = Integer.parseInt(args[2]);
        long interval = Long.parseLong(args[3]);
        long elapsed = Long.parseLong(args[4]);
        Map<String, Samples> byThread = new HashMap<>();
        long totalSamples = 0, totalWeight = 0, batchRecords = 0, executionRecords = 0;
        for (var event : RecordingFile.readAllEvents(recording)) {
            var type = event.getEventType().getName();
            boolean wall = type.equals("profiler.WallClockSample");
            boolean execution = type.equals("jdk.ExecutionSample");
            if (!wall && !execution) continue;
            require(nobatch ? execution : wall, "Wall event kind disagrees with nobatch=" + nobatch + ": " + type);
            String name = event.getThread("sampledThread").getJavaName();
            require(name != null && name.startsWith("wall-population-"), "Wall thread filter leaked: " + name);
            int index = Integer.parseInt(name.substring("wall-population-".length()));
            require(index >= 0 && index < threads, "Unknown selected thread: " + name);
            long count = wall ? event.getInt("samples") : 1;
            long span = wall ? event.getDuration("timeSpan").toNanos() : 0;
            long weight = wall ? count * interval : event.getLong("weight");
            require(count > 0 && span >= 0, "Invalid wall multiplicity/span");
            require(weight == count * interval, "Wall interval weight changed: " + weight);
            var start = event.getStartTime();
            long time = start.getEpochSecond() * 1_000_000_000L + start.getNano();
            Samples samples = byThread.computeIfAbsent(name, key -> new Samples());
            samples.count += count;
            samples.records++;
            samples.first = Math.min(samples.first, time);
            samples.last = Math.max(samples.last, time + span);
            samples.times.add(time);
            if (count > 1) samples.batched += count;
            boolean busy = index < WallPopulation.BUSY_THREADS;
            if (frame(event, busy ? "wallBusy" : "wallSleep")) samples.expectedFrames += count;
            if (event.getString("state").equals(busy ? "STATE_RUNNABLE" : "STATE_SLEEPING")) samples.expectedState += count;
            totalSamples += count;
            totalWeight += weight;
            if (wall) batchRecords++; else executionRecords++;
        }
        require(byThread.size() == threads, "Missed threads beyond first capture batch: " + byThread.keySet());
        long batchedSleep = 0;
        for (int index = 0; index < threads; index++) {
            String name = "wall-population-" + index;
            Samples samples = byThread.get(name);
            require(samples != null && samples.count >= 10, "Insufficient samples for " + name);
            long weight = samples.count * interval;
            require(weight >= elapsed * 7 / 10 && weight <= elapsed * 13 / 10,
                    "Per-thread wall weight differs from duration: " + name + " weight=" + weight + " elapsed=" + elapsed);
            require(samples.expectedFrames * 10 >= samples.count * 7,
                    "Missing workload frames: " + name + " frames=" + samples.expectedFrames + " samples=" + samples.count);
            require(samples.expectedState > 0, "Expected running/sleeping state absent: " + name);
            long mean = (samples.last - samples.first) / (samples.count - 1);
            require(mean >= interval * 7 / 10 && mean <= interval * 13 / 10,
                    "Per-thread cadence differs from interval: " + name + " mean=" + mean);
            long median = 0;
            if (nobatch) {
                Collections.sort(samples.times);
                var deltas = new ArrayList<Long>();
                for (int i = 1; i < samples.times.size(); i++) deltas.add(samples.times.get(i) - samples.times.get(i - 1));
                Collections.sort(deltas);
                median = deltas.get(deltas.size() / 2);
                require(median >= interval / 2 && median <= interval * 3 / 2,
                        "Unbatched per-thread cadence differs from interval: " + name + " median=" + median);
                require(samples.count == samples.records && samples.batched == 0, "nobatch retained idle multiplicity");
            }
            if (index >= WallPopulation.BUSY_THREADS) batchedSleep += samples.batched;
            System.out.println("WALL_THREAD name=" + name + " samples=" + samples.count + " records=" + samples.records
                    + " weightNs=" + weight + " meanNs=" + mean + " medianNs=" + median + " batched=" + samples.batched);
        }
        require(nobatch || batchedSleep > 0, "Batched mode did not exercise sleeping sample reuse");
        long nativeTotal = 0;
        for (var row : Files.readAllLines(Path.of(recording + ".collapsed")))
            nativeTotal += Long.parseLong(row.substring(row.lastIndexOf(' ') + 1));
        require(nativeTotal == totalWeight, "Native/JFR wall totals differ: " + nativeTotal + " vs " + totalWeight);
        System.out.println("WALL_POPULATION_OK mode=" + (nobatch ? "nobatch" : "batch") + " threads=" + threads
                + " samples=" + totalSamples + " totalNs=" + totalWeight + " nativeTotalNs=" + nativeTotal
                + " wallRecords=" + batchRecords + " executionRecords=" + executionRecords
                + " sleepingBatchedSamples=" + batchedSleep);
    }
}
