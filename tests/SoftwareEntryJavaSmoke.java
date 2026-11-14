/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Files;
import java.nio.file.Path;
import one.profiler.AsyncProfiler;

public final class SoftwareEntryJavaSmoke {
    private static native long call(long value);
    private static native long other(long value);

    static long prefix() { return call(100) + call(101) + call(102) + call(103); }
    static long selected() { return call(104) + call(105); }
    static long alternate() { return other(200); }

    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }

    public static void main(String[] args) throws Exception {
        AsyncProfiler profiler = AsyncProfiler.getInstance(args[0]);
        Path library = Path.of(args[1]).toAbsolutePath();
        Path directory = Path.of(args[2]);
        System.load(library.toString());
        String selector = "uprobe:" + library + "!SoftwareEntryTarget";
        profiler.execute("start,event=" + selector + ",interval=3,filter=,cstack=default,jfr,file=" + directory.resolve("java.jfr"));
        require(prefix() == 410, "Excluded native return values changed");
        profiler.addThread(Thread.currentThread());
        require(selected() == 211, "Observed native return values changed");
        profiler.execute("stop");
        Files.writeString(directory.resolve("java.total.collapsed"), profiler.execute("collapsed,total"));
        Files.writeString(directory.resolve("java.samples.collapsed"), profiler.execute("collapsed,samples"));
        profiler.execute("start,event=" + selector + ",interval=2,cstack=default,jfr,file=" + directory.resolve("java-rearm.jfr"));
        require(selected() == 211, "Rearmed native return values changed");
        profiler.execute("stop");
        Files.writeString(directory.resolve("java-rearm.total.collapsed"), profiler.execute("collapsed,total"));
        String next = "uprobe:" + library + "!SoftwareEntryAlternate";
        profiler.execute("start,event=" + next + ",cstack=default,jfr,file=" + directory.resolve("java-next.jfr"));
        require(alternate() == 207, "Alternate native return changed");
        profiler.execute("stop");
        Files.writeString(directory.resolve("java-next.total.collapsed"), profiler.execute("collapsed,total"));
        Files.writeString(directory.resolve("java-next.samples.collapsed"), profiler.execute("collapsed,samples"));
        String metrics = profiler.execute("metrics");
        System.out.print(metrics);
        require(metrics.contains("windows_software_probe_failed 0\n")
            && metrics.contains("windows_software_probe_dropped 0\n")
            && metrics.contains("windows_software_probe_unprepared 0\n"), metrics);
        System.out.println("SOFTWARE_ENTRY_JAVA_OK selector=" + selector + " next=" + next);
    }
}
