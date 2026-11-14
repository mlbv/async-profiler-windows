/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
package opt.sample;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.Deflater;
import one.profiler.AsyncProfiler;

/** Records a lambda-driven CPU workload and writes it with each frame-naming, filtering and rendering option. */
public final class OutputOptions {
    static volatile long sink;

    static long burn(int rounds, String label) {
        long value = label.length();
        for (int i = 0; i < rounds; i++) value = value * 31 + i;
        return value;
    }

    // Native frames come from zip.dll's deflate code.
    static int compress(byte[] input, byte[] output) {
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
        deflater.setInput(input);
        deflater.finish();
        int size = deflater.deflate(output);
        deflater.end();
        return size;
    }

    static void work(long nanos) throws InterruptedException {
        byte[] input = new byte[1 << 20], output = new byte[2 << 20];
        for (int i = 0; i < input.length; i++) input[i] = (byte) (i * 2654435761L >>> 13);
        Runnable task = () -> {
            long end = System.nanoTime() + nanos;
            while (System.nanoTime() < end) sink += burn(30_000_000, "options") + compress(input, output);
        };
        Thread worker = new Thread(task, "options-worker");
        worker.start();
        worker.join();
    }

    public static void main(String[] args) throws Exception {
        AsyncProfiler profiler = AsyncProfiler.getInstance(Path.of(args[0]).toAbsolutePath().toString());
        Path out = Path.of(args[1]);
        work(500_000_000L);
        String[][] recordings = {{"plain", ""}, {"threads", ",threads"}, {"sched", ",sched"}};
        String[][] formats = {
            {"collapsed", "plain.collapsed"}, {"collapsed,simple", "simple.collapsed"}, {"collapsed,norm", "norm.collapsed"},
            {"collapsed,sig", "sig.collapsed"}, {"collapsed,ann", "ann.collapsed"}, {"collapsed,lib", "lib.collapsed"},
            {"collapsed,dot", "dot.collapsed"}, {"collapsed,include=*burn*", "include.collapsed"},
            {"collapsed,exclude=*burn*", "exclude.collapsed"}, {"flamegraph", "default.html"},
            {"flamegraph,title=Options Graph,minwidth=2", "titled.html"}, {"flamegraph,reverse", "reverse.html"},
            {"flamegraph,inverted", "inverted.html"}, {"tree", "tree.html"}, {"traces=3", "traces.txt"}, {"flat=3", "flat.txt"}};
        for (String[] recording : recordings) {
            profiler.execute("start,event=cpu,interval=1ms" + recording[1]);
            work(1_000_000_000L);
            profiler.stop();
            if (recording[0].equals("plain")) {
                for (String[] format : formats) Files.writeString(out.resolve(format[1]), profiler.execute(format[0]));
            } else {
                Files.writeString(out.resolve(recording[0] + ".collapsed"), profiler.execute("collapsed"));
            }
        }
        System.out.println("OUTPUT_OPTIONS_WRITTEN");
    }
}
