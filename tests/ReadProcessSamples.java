/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashMap;
import jdk.jfr.consumer.RecordingFile;
import one.jfr.JfrReader;
import one.jfr.event.ProcessSample;
import one.jfr.event.WindowsProcessMetrics;

public final class ReadProcessSamples {
    public static void main(String[] args) throws Exception {
        var parent = Integer.parseInt(args[1]);
        var pids = new int[]{Integer.parseInt(args[2]), Integer.parseInt(args[3])};
        var samples = new HashMap<Integer, Integer>();
        var windows = new HashMap<Integer, Integer>();
        try (var recording = new RecordingFile(Path.of(args[0]))) {
            while (recording.hasMoreEvents()) {
                var event = recording.readEvent();
                var type = event.getEventType().getName();
                if (!type.equals("profiler.ProcessSample") && !type.equals("profiler.WindowsProcessMetrics")) continue;
                var pid = event.getInt("pid");
                if (pid != pids[0] && pid != pids[1]) continue;
                if (type.equals("profiler.ProcessSample")) {
                    if (event.getInt("ppid") != parent || !event.getString("name").equals("进程.exe")) throw new AssertionError("Wrong process identity: " + event);
                    var command = event.getString("cmdLine");
                    if (!command.contains("进程🙂.bin") || command.contains("\ufffd")) throw new AssertionError("Corrupt command line: " + event);
                    var percent = event.getFloat("cpuPercent");
                    if (!(percent >= 0.05 && percent < 2) || event.getFloat("cpuUser") <= 0) throw new AssertionError("Invalid CPU counters: " + event);
                    if (event.getInt("threads") < 1 || event.getLong("vmRss") < 32 * 1024 * 1024L
                            || event.getLong("vmSize") < event.getLong("vmRss")) throw new AssertionError("Invalid process memory/thread counts: " + event);
                    if (event.getLong("ioWrite") < 8 * 1024 * 1024L) throw new AssertionError("I/O is not measured in bytes: " + event);
                    if (Math.abs(Instant.now().toEpochMilli() - event.getLong("processStartTime")) > 120_000) throw new AssertionError("Wrong process start time");
                    for (var field : java.util.List.of("uid", "rssAnon", "rssFiles", "rssShmem", "minorFaults", "majorFaults")) {
                        if (event.getLong(field) != 0 || !event.getEventType().getField(field).getLabel().contains("unavailable")) throw new AssertionError("Misrepresented POSIX field " + field);
                    }
                    samples.merge(pid, 1, Integer::sum);
                } else {
                    var flags = event.getInt("availableFields");
                    if ((flags & 31) != 31 || !event.getString("userSid").startsWith("S-1-")) throw new AssertionError("Missing optional Windows fields: " + event);
                    if (pid == pids[1] && (flags & 32) == 0) throw new AssertionError("Long command line was not marked truncated");
                    if (event.getLong("pageFaults") < 16000 || event.getLong("privateWorkingSet") < 32 * 1024 * 1024L
                            || event.getLong("privateCommit") < 64 * 1024 * 1024L) throw new AssertionError("Invalid Windows counters: " + event);
                    windows.merge(pid, 1, Integer::sum);
                }
            }
        }
        for (var pid : pids) if (samples.getOrDefault(pid, 0) < 2 || !samples.get(pid).equals(windows.get(pid))) throw new AssertionError("Missing paired process events: " + samples + " " + windows);
        var generic = 0;
        var platform = 0;
        try (var reader = new JfrReader(args[0])) {
            for (var event = reader.readEvent(); event != null; event = reader.readEvent()) {
                if (event instanceof ProcessSample process && (process.pid == pids[0] || process.pid == pids[1])) generic++;
                if (event instanceof WindowsProcessMetrics process && (process.pid == pids[0] || process.pid == pids[1])) platform++;
            }
        }
        if (generic < 4 || platform != generic) throw new AssertionError("Converter could not read both process event types");
        System.out.println("processSamples=" + generic + " windowsMetrics=" + platform + " x64/x86 Unicode/counters=OK");
    }
}
