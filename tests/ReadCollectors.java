/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;

public final class ReadCollectors {
    static boolean frame(RecordedEvent event, String method) {
        if (event.getStackTrace() == null) return false;
        for (var frame : event.getStackTrace().getFrames()) {
            if (frame.getMethod().getName().equals("stale_jmethodID")) throw new AssertionError("Stale method metadata");
            if (frame.getMethod().getType().getName().equals("CollectorSmoke") && frame.getMethod().getName().equals(method)) {
                if (frame.getLineNumber() <= 0) throw new AssertionError("Missing workload source line");
                return true;
            }
        }
        return false;
    }

    static boolean compiledAllocation(RecordedEvent event) {
        if (event.getStackTrace() == null) return false;
        var frames = event.getStackTrace().getFrames();
        return frames.size() >= 2 && frames.get(0).getType().equals("JIT compiled")
                && frames.get(0).getMethod().getName().equals("allocateCompiled") && frames.get(1).getMethod().getName().equals("main");
    }

    public static void main(String[] args) throws Exception {
        var mode = args[1];
        var wall = mode.startsWith("wall");
        var live = mode.startsWith("live");
        var mixedLive = mode.equals("live-mixed");
        var wallInterval = mode.equals("wall-supplementary") ? 7_000_000L : 5_000_000L;
        var events = 0L;
        var total = 0L;
        var retained = 0;
        var discarded = 0;
        var monitor = 0;
        var parks = 0;
        var timedParks = 0;
        var sleeping = 0L;
        var running = 0L;
        var outside = 0;
        var compiled = 0;
        var historicalDiscarded = 0;
        var cpuTotal = 0L;
        var allocationHistory = 0L;
        var threads = new HashSet<String>();
        for (var event : RecordingFile.readAllEvents(Path.of(args[0]))) {
            var type = event.getEventType().getName();
            if (mode.equals("wall-resume") && type.equals("jdk.ActiveSetting") && event.getString("name").equals("event")
                    && event.getString("value").equals("cpu")) wallInterval = 7_000_000L;
            if ((wall || mixedLive) && type.equals("jdk.ExecutionSample")) cpuTotal += event.getLong("weight");
            if (live && (type.equals("jdk.ObjectAllocationInNewTLAB") || type.equals("jdk.ObjectAllocationOutsideTLAB"))) {
                if (frame(event, "allocateDiscarded")) historicalDiscarded++;
                if (mixedLive) allocationHistory += event.getLong(type.equals("jdk.ObjectAllocationInNewTLAB") ? "tlabSize" : "allocationSize");
            }
            if (wall && type.equals("profiler.WallClockSample")) {
                var samples = event.getInt("samples");
                if (samples <= 0 || event.getDuration("timeSpan").isNegative()) throw new AssertionError("Invalid wall batch");
                var thread = event.getThread("sampledThread").getJavaName();
                threads.add(thread);
                if (thread.equals("collector-sleeper") && frame(event, "wallSleep") && event.getString("state").equals("STATE_SLEEPING")) sleeping += samples;
                if (thread.equals("collector-main") && frame(event, "wallBusy") && event.getString("state").equals("STATE_RUNNABLE")) running += samples;
                events += samples;
                total += samples * wallInterval;
            } else if (mode.equals("lock") && (type.equals("jdk.JavaMonitorEnter") || type.equals("jdk.ThreadPark"))) {
                var duration = event.getDuration().toNanos();
                if (duration <= 0 || event.getLong("address") == 0) throw new AssertionError("Invalid lock duration/address");
                if (type.equals("jdk.JavaMonitorEnter") && frame(event, "contendMonitor") && event.getClass("monitorClass").getName().equals("java.lang.Object")) monitor++;
                if (type.equals("jdk.ThreadPark") && event.getClass("parkedClass").getName().startsWith("java.util.concurrent.locks.ReentrantLock")) {
                    if (frame(event, "contendLock") && event.getLong("timeout") == 0) parks++;
                    if (frame(event, "contendTimedLock") && event.getLong("timeout") > 0) timedParks++;
                }
                events++;
                total += duration;
            } else if ((mode.equals("alloc") || mode.equals("tlab"))
                    && (type.equals("jdk.ObjectAllocationInNewTLAB") || type.equals("jdk.ObjectAllocationOutsideTLAB"))
                    || live && type.equals("profiler.LiveObject")) {
                var size = event.getLong("allocationSize");
                if (size <= 0) throw new AssertionError("Invalid allocation size");
                if (event.getClass("objectClass").getName().equals("[B")) {
                    if (frame(event, "allocateRetained")) retained++;
                    if (frame(event, "allocateDiscarded")) discarded++;
                    if (compiledAllocation(event)) compiled++;
                }
                if (type.equals("profiler.LiveObject")) {
                    if (event.getInstant("allocationTime").isAfter(event.getStartTime())) throw new AssertionError("Live object predates allocation");
                }
                if (type.equals("jdk.ObjectAllocationInNewTLAB")) {
                    var bytes = event.getLong("tlabSize");
                    if (bytes < size) throw new AssertionError("Allocation exceeds recorded sampled bytes");
                    total += bytes;
                } else {
                    if (type.equals("jdk.ObjectAllocationOutsideTLAB")) outside++;
                    total += size;
                }
                events++;
            }
        }
        if (wall && (sleeping < 10 || running < 10 || !threads.equals(java.util.Set.of("collector-main", "collector-sleeper")))) {
            throw new AssertionError("Wall filter/state/stack mismatch: sleeping=" + sleeping + " running=" + running + " threads=" + threads);
        }
        if (mode.equals("lock") && (monitor < 3 || parks < 3 || timedParks < 3)) {
            throw new AssertionError("Missing contended paths: monitor=" + monitor + " parks=" + parks + " timed=" + timedParks);
        }
        if ((mode.equals("alloc") || live) && retained < 32 || live && (discarded != 0 || historicalDiscarded < 32)
                || mode.equals("alloc") && discarded < 32 || mode.equals("tlab") && (outside == 0 || compiled < 8)) {
            throw new AssertionError("Allocation/liveness paths missing: retained=" + retained + " discarded=" + discarded + " outside=" + outside + " compiled=" + compiled);
        }
        var nativeTotal = 0L;
        for (var line : Files.readAllLines(Path.of(args[0] + ".collapsed"))) {
            var value = Long.parseLong(line.substring(line.lastIndexOf(' ') + 1));
            nativeTotal += value;
        }
        System.out.println("COLLECTOR_COUNTS mode=" + mode + " events=" + events + " total=" + total + " nativeTotal=" + nativeTotal
                + " cpuTotal=" + cpuTotal + " allocationHistory=" + allocationHistory + " retained=" + retained + " discarded=" + discarded + " historicalDiscarded=" + historicalDiscarded + " compiled=" + compiled + " monitor=" + monitor + " parks=" + parks + " timed=" + timedParks);
        if (mixedLive && cpuTotal == 0) throw new AssertionError("Mixed profile did not exercise CPU weight retention");
        if (events == 0 || nativeTotal != total + cpuTotal + allocationHistory) throw new AssertionError("Collector aggregate mismatch: native=" + nativeTotal + " JFR=" + total + " CPU=" + cpuTotal);
    }
}
