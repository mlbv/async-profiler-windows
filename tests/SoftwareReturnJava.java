/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Files;
import java.nio.file.Path;
import one.profiler.AsyncProfiler;

public final class SoftwareReturnJava {
    private static native long framed(long value);
    private static native long multiple(long value);

    interface Workload { long run() throws Exception; }

    static long chosen() {
        long sum = 0;
        for (int index = 0; index < 6; index++) sum += framed(index);
        return sum;
    }
    static long branched() {
        long sum = 0;
        for (int index = 0; index < 4; index++) sum += multiple(index);
        return sum;
    }
    static long napping() throws InterruptedException {
        for (int index = 0; index < 7; index++) Thread.sleep(0);
        return 7;
    }
    static long asserting() {
        long enabled = 0;
        for (int index = 0; index < 5; index++) enabled += String.class.desiredAssertionStatus() ? 1 : 0;
        return enabled;
    }

    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }

    private static void record(AsyncProfiler profiler, Path directory, String name, String selector, int period,
            Workload workload, long expected) throws Exception {
        profiler.execute("start,event=" + selector + ",interval=" + period + ",filter=,cstack=default,jfr,file="
            + directory.resolve(name + ".jfr"));
        profiler.addThread(Thread.currentThread());
        require(workload.run() == expected, name + " changed its result");
        profiler.execute("stop");
        Files.writeString(directory.resolve(name + ".total.collapsed"), profiler.execute("collapsed,total"));
        Files.writeString(directory.resolve(name + ".samples.collapsed"), profiler.execute("collapsed,samples"));
        System.out.println("JAVA_RETURN_CAPTURE name=" + name + " selector=" + selector);
    }

    public static void main(String[] args) throws Exception {
        AsyncProfiler profiler = AsyncProfiler.getInstance(args[0]);
        Path library = Path.of(args[1]).toAbsolutePath();
        Path directory = Path.of(args[2]);
        System.load(library.toString());
        String fixture = "uretprobe:" + library + "!";
        record(profiler, directory, "java-framed", fixture + "ReturnFramed", 2, SoftwareReturnJava::chosen, 15 + 12);
        record(profiler, directory, "java-framed-rearm", fixture + "ReturnFramed", 3, SoftwareReturnJava::chosen, 15 + 12);
        record(profiler, directory, "java-jni", fixture + "Java_SoftwareReturnJava_multiple", 1, SoftwareReturnJava::branched,
            (0 + 4) + (1 + 3) + (2 + 4) + (3 + 3) + 4);
        // MSVC-built JVM functions with nine and five chained unwind rows.
        record(profiler, directory, "java-sleep", "uretprobe:jvm.dll!JVM_SleepNanos", 1, SoftwareReturnJava::napping, 7);
        record(profiler, directory, "java-assert", "uretprobe:jvm.dll!JVM_DesiredAssertionStatus", 1,
            SoftwareReturnJava::asserting, 0);
        String metrics = profiler.execute("metrics");
        System.out.print(metrics);
        require(metrics.contains("windows_software_probe_failed 0\n")
            && metrics.contains("windows_software_probe_dropped 0\n")
            && metrics.contains("windows_software_probe_unprepared 0\n"), metrics);
        System.out.println("SOFTWARE_RETURN_JAVA_OK");
    }
}
