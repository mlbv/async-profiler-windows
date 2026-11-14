/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.TreeMap;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;
import one.profiler.AsyncProfiler;

public final class StandaloneSmoke {
    public static void main(String[] args) throws Exception {
        AsyncProfiler profiler = AsyncProfiler.getInstance(Paths.get(args[0]).toAbsolutePath().toString());
        System.out.print(profiler.getVersion());
        Path file = Paths.get(args[1]).toAbsolutePath();
        System.out.println(profiler.execute("start,jfr,file=" + file + ",log=stderr," + args[2]));
        try {
            Fixture.main(new String[]{"3"});
        } finally {
            profiler.stop();
        }
        Files.write(Paths.get(file + ".collapsed"), profiler.execute("collapsed,total").getBytes(StandardCharsets.UTF_8));
        Map<String, Integer> counts = new TreeMap<>();
        for (RecordedEvent event : RecordingFile.readAllEvents(file)) {
            counts.merge(event.getEventType().getName(), 1, Integer::sum);
        }
        System.out.println(counts);
        if (counts.getOrDefault(args[3], 0) == 0) throw new AssertionError("No " + args[3] + " events");
        if (args[3].equals("jdk.ExecutionSample")) ReadVmStacks.main(new String[]{file.toString(), "default"});
    }
}
