/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import one.profiler.AsyncProfiler;

public final class CompilerTaskSmoke {
    public static void main(String[] args) throws Exception {
        var profiler = AsyncProfiler.getInstance(Path.of(args[0]).toAbsolutePath().toString());
        test.comptask.Main.main(new String[0]);
        profiler.stop();
        var text = profiler.execute("metrics");
        System.out.println(text);
        var metrics = new HashMap<String, Long>();
        for (var line : text.split("\n")) {
            var words = line.split(" ");
            if (words.length == 2 && (words[0].startsWith("windows_comptask_") || words[0].equals("windows_agct_calls"))) {
                metrics.put(words[0], Long.parseLong(words[1]));
            }
        }
        var calls = metrics.get("windows_comptask_calls");
        var tasks = metrics.get("windows_comptask_frames");
        if (tasks == 0 || calls < tasks || metrics.get("windows_comptask_apc_failures") != 0 || metrics.get("windows_agct_calls") != 0) {
            throw new AssertionError("Compiler target JNI/task path was not exercised: " + metrics);
        }
        Files.writeString(Path.of(args[1]), profiler.execute("collapsed,total"));
        System.out.println("COMPILER_TARGET_TLS_OK calls=" + calls + " tasks=" + tasks);
    }
}
