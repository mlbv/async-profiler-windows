/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.channels.FileChannel;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import jdk.jfr.Event;
import jdk.jfr.FlightRecorder;
import jdk.jfr.Name;
import one.profiler.AsyncProfiler;
import one.profiler.Span;

public final class LifecycleLimitSmoke {
    @Name("test.LifecyclePhase")
    static final class Phase extends Event {
        int phase;
    }

    static volatile long result;

    static void beforeResume() {
        var value = result;
        for (var i = 0; i < 100_000; i++) value = Long.rotateLeft(value ^ i, 13) * 0x100000001b3L;
        result = value;
    }

    static void afterResume() {
        var value = result;
        for (var i = 0; i < 100_000; i++) value = Long.rotateLeft(value ^ i, 17) * 0x100000001b3L;
        result = value;
    }

    static void burn(boolean after, long millis) {
        var until = System.nanoTime() + millis * 1_000_000L;
        while (System.nanoTime() < until) {
            if (after) afterResume(); else beforeResume();
        }
    }

    static int awaitStop(AsyncProfiler profiler, long deadlineMillis) throws Exception {
        var checksUntil = deadlineMillis + 10_000;
        var samples = profiler.getSamples();
        var resets = 0;
        while (System.currentTimeMillis() < checksUntil) {
            burn(false, 25);
            var current = profiler.getSamples();
            if (current < samples) resets++;
            samples = current;
            if (!profiler.execute("status").contains("not active")) continue;
            var now = System.currentTimeMillis();
            if (now < deadlineMillis - 200 || now > deadlineMillis + 1500) {
                throw new AssertionError("Absolute stop missed deadline: now=" + now + " expected=" + deadlineMillis);
            }
            System.out.println("ABSOLUTE_STOP_OK deadline=" + deadlineMillis + " observed=" + now + " resets=" + resets);
            return resets;
        }
        throw new AssertionError("Absolute timeout never stopped");
    }

    static String absolute(long epochMillis) {
        return LocalDateTime.ofInstant(java.time.Instant.ofEpochMilli(epochMillis), java.time.ZoneId.systemDefault())
                .format(DateTimeFormatter.ofPattern("HH:mm:ss"));
    }

    public static void main(String[] args) throws Exception {
        var profiler = AsyncProfiler.getInstance(Path.of(args[0]).toAbsolutePath().toString());
        var directory = Path.of(args[1]);
        var sync = args[2].startsWith("sync");
        FlightRecorder.register(Phase.class);
        burn(false, 500);
        burn(true, 500);
        var recording = directory.resolve("resume.jfr");
        var options = ",event=cpu,interval=1ms,cstack=no,jfr" + (sync ? ",jfrsync=+test.LifecyclePhase" : "") + ",file=" + recording;
        profiler.execute("start" + options);
        var first = new Phase();
        first.phase = 1;
        first.commit();
        var firstSpan = Span.start();
        burn(false, 750);
        Span.end(firstSpan, "before-resume-𠮷");
        if (args[2].endsWith("-exit")) {
            System.out.println("RECORDER_EXIT_PENDING");
            return;
        }
        if (args[2].endsWith("-external")) {
            var masters = FlightRecorder.getFlightRecorder().getRecordings().stream()
                    .filter(active -> active.getState() == jdk.jfr.RecordingState.RUNNING).toList();
            if (masters.size() != 1) throw new AssertionError("Unexpected active JVM recordings: " + masters.size());
            masters.get(0).stop();
            if (!profiler.execute("status").contains("not active")) throw new AssertionError("JVM stop did not stop native recording");
            Files.writeString(Path.of(recording + ".collapsed"), profiler.execute("collapsed,total"));
            System.out.println("RECORDER_EXTERNAL_STOP_OK");
            return;
        }
        if (args[2].endsWith("-failure")) {
            try (var channel = FileChannel.open(recording, StandardOpenOption.WRITE);
                 var lock = channel.lock()) {
                try {
                    profiler.execute("stop");
                    throw new AssertionError("Locked recording stop incorrectly succeeded");
                } catch (Exception e) {
                    if (!e.getMessage().contains("Cannot")) throw e;
                    System.out.println("STOP_FAILURE_CAUGHT " + e);
                }
            }
            if (!profiler.execute("status").contains("not active")) throw new AssertionError("Failed stop left profiler active");
            var released = Path.of(recording + ".released");
            Files.move(recording, released);
            Files.move(released, recording);
            if (sync) {
                var recovery = Path.of(recording + ".native-recovery");
                if (!Files.isRegularFile(recovery)) throw new AssertionError("Native recovery data missing");
                Files.writeString(Path.of(recovery + ".collapsed"), profiler.execute("collapsed,total"));
            }
            System.out.println("RECORDER_FAILURE_OK sync=" + sync);
            return;
        }
        profiler.execute("stop");
        var original = Files.readAllBytes(recording);
        var previousSamples = profiler.getSamples();
        if (previousSamples == 0) throw new AssertionError("No samples before resume");
        profiler.execute("resume" + options);
        var second = new Phase();
        second.phase = 2;
        second.commit();
        var secondSpan = Span.start();
        burn(true, 750);
        Span.end(secondSpan, "after-resume-𠮷");
        var snapshot = directory.resolve("resume-snapshot.jfr");
        profiler.execute("dump,jfr,file=" + snapshot);
        var snapshotBytes = Files.readAllBytes(snapshot);
        if (snapshotBytes.length <= original.length) throw new AssertionError("Resumed snapshot lost prior data");
        for (var i = 0; i < original.length; i++) {
            if (snapshotBytes[i] != original[i]) throw new AssertionError("Resumed snapshot changed prior byte " + i);
        }
        profiler.execute("stop");
        var resumed = Files.readAllBytes(recording);
        if (resumed.length <= original.length) throw new AssertionError("Resume replaced prior data");
        for (var i = 0; i < original.length; i++) {
            if (resumed[i] != original[i]) throw new AssertionError("Resume changed prior recording byte " + i);
        }
        if (profiler.getSamples() <= previousSamples) throw new AssertionError("Resume discarded aggregate counters");
        Files.writeString(Path.of(recording + ".collapsed"), profiler.execute("collapsed,total"));
        System.out.println("RESUME_PREFIX_OK sync=" + sync + " retained=" + original.length + " total=" + resumed.length);

        var stop = (System.currentTimeMillis() / 1000 + 3) * 1000;
        recording = directory.resolve("absolute.jfr");
        profiler.execute("start,event=cpu,interval=1ms,cstack=no,jfr,timeout=" + absolute(stop) + ",file=" + recording);
        awaitStop(profiler, stop);
        System.out.println("CAPTURE_LIMIT " + stop + " " + recording);
        Files.writeString(Path.of(recording + ".collapsed"), profiler.execute("collapsed,total"));

        var loop = (System.currentTimeMillis() / 1000 + 2) * 1000;
        stop = loop + 2000;
        profiler.execute("start,event=cpu,interval=1ms,cstack=no,jfr,loop=" + absolute(loop)
                + ",timeout=" + absolute(stop) + ",file=" + directory.resolve("absolute-loop-%n.jfr"));
        if (awaitStop(profiler, stop) != 1) throw new AssertionError("Absolute loop failed to rotate exactly once");
        for (var i = 0; i < 2; i++) {
            recording = directory.resolve("absolute-loop-" + i + ".jfr");
            if (!Files.isRegularFile(recording)) throw new AssertionError("Missing absolute loop file " + recording);
            System.out.println("CAPTURE_LIMIT " + (i == 0 ? loop : stop) + " " + recording);
        }
        System.out.println("LIFECYCLE_LIMIT_SMOKE_OK");
    }
}
