/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Files;
import java.nio.file.Path;
import jdk.jfr.consumer.RecordingFile;
import one.profiler.AsyncProfiler;

public final class StopCopySmoke {
    static volatile long result;

    static void burn() {
        var value = result;
        for (var i = 0; i < 100_000; i++) value = Long.rotateLeft(value ^ i, 13) * 0x100000001b3L;
        result = value;
    }

    public static void main(String[] args) throws Exception {
        var profiler = AsyncProfiler.getInstance(args[0]);
        var directory = Path.of(args[1]);
        for (var i = 0; i < 1000; i++) burn();
        for (var mode : new String[]{"exact", "hardlink", "blocked"}) {
            var original = directory.resolve("same-" + mode + ".jfr");
            var destination = mode.equals("exact") ? original : directory.resolve("same-" + mode + "-destination.jfr");
            if (mode.equals("blocked")) Files.writeString(destination, "preserve-existing-copy-destination");
            profiler.execute("start,event=cpu,interval=1ms,jfr,file=" + original);
            try {
                var end = System.nanoTime() + 1_000_000_000L;
                while (System.nanoTime() < end) burn();
                if (mode.equals("hardlink")) Files.createLink(destination, original);
                try {
                    profiler.execute("stop,jfr,file=" + destination);
                    if (mode.equals("blocked")) throw new AssertionError("Copy collision was ignored");
                } catch (Exception error) {
                    if (!mode.equals("blocked") || !error.getMessage().contains("Cannot create finalized JFR copy")) throw error;
                }
            } finally {
                if (!profiler.execute("status").contains("not active")) profiler.stop();
            }
            if (mode.equals("blocked")) {
                if (!Files.readString(destination).equals("preserve-existing-copy-destination")) throw new AssertionError("Copy collision truncated existing output");
            } else if (Files.mismatch(original, destination) != -1) throw new AssertionError("Same-file output changed: " + mode);
            var samples = 0;
            for (var event : RecordingFile.readAllEvents(original)) {
                if (event.getEventType().getName().equals("jdk.ExecutionSample") && event.getLong("weight") > 0) samples++;
            }
            if (samples == 0) throw new AssertionError("Missing finalized native samples: " + mode);
            System.out.println("NATIVE_STOP_COPY_OK mode=" + mode + " samples=" + samples);
        }
    }
}
