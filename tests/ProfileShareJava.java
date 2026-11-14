/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import one.profiler.AsyncProfiler;

/** Java target for concurrent ETW timer captures, driven one command per stdin line like the native share fixture. */
public final class ProfileShareJava {
    static volatile long sink;

    static void spin(long milliseconds) {
        var end = System.nanoTime() + milliseconds * 1_000_000;
        var value = 1L;
        while (System.nanoTime() < end) {
            for (int i = 0; i < 10000; i++) value = (value ^ (value >>> 13)) * 0x100000001b3L;
        }
        sink = value;
    }

    static void shareWorkBefore(long milliseconds) { spin(milliseconds); }

    static void shareWorkDuring(long milliseconds) { spin(milliseconds); }

    static void shareWorkAfter(long milliseconds) { spin(milliseconds); }

    public static void main(String[] args) throws Exception {
        // agent output-directory local|broker
        var profiler = AsyncProfiler.getInstance(Path.of(args[0]).toAbsolutePath().toString());
        var directory = Path.of(args[1]);
        var transport = args[2].equals("broker") ? ",fdtransfer" : "";
        shareWorkBefore(200);
        shareWorkDuring(200);
        shareWorkAfter(200);
        System.out.println("READY " + ProcessHandle.current().pid());
        var input = new BufferedReader(new InputStreamReader(System.in));
        for (String line; (line = input.readLine()) != null; ) {
            var parts = line.split(" ");
            switch (parts[0]) {
                case "start" -> {
                    var interval = parts[3].equals("-") ? "" : ",interval=" + parts[3];
                    try {
                        profiler.execute("start,event=" + parts[2] + interval + transport + ",jfr,file=" + directory.resolve(parts[1] + ".jfr"));
                        System.out.println("STARTED " + parts[1]);
                    } catch (IllegalStateException failure) {
                        System.out.println("FAILED " + parts[1] + " " + failure.getMessage());
                    }
                }
                case "work" -> {
                    var milliseconds = Long.parseLong(parts[2]);
                    switch (parts[1]) {
                        case "before" -> shareWorkBefore(milliseconds);
                        case "during" -> shareWorkDuring(milliseconds);
                        default -> shareWorkAfter(milliseconds);
                    }
                    System.out.println("WORKED " + parts[1]);
                }
                case "stop" -> {
                    var base = directory.resolve(parts[1]).toString();
                    profiler.stop();
                    Files.writeString(Path.of(base + ".collapsed"), profiler.execute("collapsed,total"));
                    Files.writeString(Path.of(base + ".samples.collapsed"), profiler.execute("collapsed,samples"));
                    profiler.execute("otlp,total,file=" + base + ".native.otlp");
                    Files.writeString(Path.of(base + ".metrics"), profiler.execute("metrics"));
                    System.out.println("STOPPED " + parts[1]);
                }
                case "exit" -> {
                    System.out.println("EXITED");
                    return;
                }
                default -> throw new IllegalArgumentException("Unknown command: " + line);
            }
        }
        throw new IllegalStateException("Command input closed");
    }
}
