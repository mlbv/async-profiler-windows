/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Files;
import java.nio.file.Path;
import one.profiler.AsyncProfiler;

public final class StackDepthSmoke {
    static volatile long result;

    static long burn(long value) {
        for (var i = 0; i < 5000; i++) value = Long.rotateLeft(value ^ i, 13) * 0x100000001b3L;
        return value;
    }

    static void work(long millis) {
        var end = System.nanoTime() + millis * 1_000_000L;
        while (System.nanoTime() < end) result = DeepStackPayload.m0(result);
    }

    public static void main(String[] args) throws Exception {
        var profiler = AsyncProfiler.getInstance(Path.of(args[0]).toAbsolutePath().toString());
        var directory = Path.of(args[1]);
        work(1000);
        var depths = args.length > 2 && args[2].equals("physical") ? new String[]{"1024"}
                : new String[]{"1024", "64", "64/12", "64/0"};
        for (var cstack : new String[]{"dwarf", "no"}) {
            for (var depth : depths) {
                var output = directory.resolve(cstack + "-" + depth.replace('/', '-') + ".jfr");
                profiler.execute("start,event=etw:Timer,interval=1ms,alluser,cstack=" + cstack
                        + ",jstackdepth=" + depth + ",jfr,file=" + output);
                try { work(1000); } finally { profiler.stop(); }
                Files.writeString(Path.of(output + ".collapsed"), profiler.execute("collapsed,total"));
                System.out.println("DEPTH_RECORDING " + cstack + " " + depth);
                System.out.println(profiler.execute("metrics"));
            }
        }
    }
}
