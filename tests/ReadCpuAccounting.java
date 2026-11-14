/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Files;
import java.nio.file.Path;
import jdk.jfr.consumer.RecordingFile;

public final class ReadCpuAccounting {
    public static void main(String[] args) throws Exception {
        var tid = Long.parseLong(args[1]);
        var user = Long.parseLong(args[2]);
        var kernel = Long.parseLong(args[3]);
        var userOnly = Boolean.parseBoolean(args[4]);
        var expected = userOnly ? user : user + kernel;
        var interval = args.length > 6 ? Long.parseLong(args[6]) : 0;
        var weight = 0L;
        var samples = 0;
        var minimumWeight = Long.MAX_VALUE;
        var maximumWeight = 0L;
        var unit = "";
        var intervalSeen = false;
        var eventSeen = false;
        var threadIncludeSeen = false;
        var userOnlySeen = false;
        for (var event : RecordingFile.readAllEvents(Path.of(args[0]))) {
            var name = event.getEventType().getName();
            if (name.equals("jdk.ActiveSetting")) {
                var setting = event.getString("name");
                var value = event.getString("value");
                if (setting.equals("counterUnit")) {
                    unit = value;
                    if (interval != 0 && !value.equals("ns")) throw new AssertionError("Wrong CPU counter unit: " + value);
                }
                if (interval != 0) {
                    switch (setting) {
                        case "interval" -> {
                            if (!value.equals(Long.toString(interval))) throw new AssertionError("Wrong requested CPU interval: " + value);
                            intervalSeen = true;
                        }
                        case "event" -> {
                            if (!value.equals("cpu")) throw new AssertionError("Wrong requested event: " + value);
                            eventSeen = true;
                        }
                        case "ithread" -> {
                            if (!value.equals("cpu-accounting-worker")) throw new AssertionError("Wrong CPU thread include pattern: " + value);
                            threadIncludeSeen = true;
                        }
                        case "alluser" -> {
                            if (!value.equals(Boolean.toString(userOnly))) throw new AssertionError("Wrong CPU domain: " + value);
                            userOnlySeen = true;
                        }
                    }
                }
            }
            if (!name.equals("jdk.ExecutionSample")) continue;
            if (event.getThread("sampledThread").getOSThreadId() != tid) throw new AssertionError("CPU filter admitted a foreign thread");
            var value = event.getLong("weight");
            // A thread is sampled at the poll nearest its interval boundary. Polls land at random points
            // of consecutive slots of half the interval, or of an even fraction of it no longer than 50 ms
            // but at least 1 ms, so the next poll is less than two slots away.
            var poll = interval == 0 ? 0 : Math.max(1_000_000L, interval / (2 * ((interval + 99_999_999L) / 100_000_000L)));
            if (value <= 0 || value < interval - Math.min(interval - 1, poll)) throw new AssertionError("CPU weight below the interval boundary: " + value + " interval=" + interval);
            weight += value;
            minimumWeight = Math.min(minimumWeight, value);
            maximumWeight = Math.max(maximumWeight, value);
            samples++;
        }
        if (interval != 0 && !(intervalSeen && eventSeen && threadIncludeSeen && userOnlySeen)) {
            throw new AssertionError("Missing requested CPU interval/event/thread include/domain metadata");
        }
        if (args[5].equals("kernel") && kernel < 200_000_000L || args[5].equals("user") && user < 200_000_000L) {
            throw new AssertionError("Workload did not exercise its requested CPU domain: user=" + user + " kernel=" + kernel);
        }
        var tolerance = Math.max(50_000_000L, expected / 10);
        if (!unit.equals("ns") || Math.abs(weight - expected) > tolerance || expected > tolerance && samples == 0) {
            throw new AssertionError("CPU accounting mismatch: userOnly=" + userOnly + " user=" + user + " kernel=" + kernel
                    + " expected=" + expected + " actual=" + weight + " samples=" + samples + " unit=" + unit);
        }
        if (args.length > 7) {
            var collapsed = 0L;
            for (var line : Files.readAllLines(Path.of(args[7]))) {
                if (line.isBlank()) continue;
                var value = Long.parseLong(line.substring(line.lastIndexOf(' ') + 1));
                if (value <= 0) throw new AssertionError("Nonpositive collapsed CPU weight");
                collapsed += value;
            }
            if (collapsed != weight) throw new AssertionError("CPU export mismatch: JFR=" + weight + " collapsed=" + collapsed);
        }
        System.out.println("CPU_ACCOUNTING_OK userOnly=" + userOnly + " user=" + user + " kernel=" + kernel
                + " sampled=" + weight + " samples=" + samples + " interval=" + interval
                + " minimumWeight=" + (samples == 0 ? 0 : minimumWeight) + " maximumWeight=" + maximumWeight);
    }
}
