/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordedFrame;
import jdk.jfr.consumer.RecordedMethod;
import jdk.jfr.consumer.RecordingFile;
import one.profiler.AsyncProfiler;

public final class UnicodeJvmSmoke {
    static volatile Object retained;
    static volatile long result;
    static final class 对象𠮷 {
        long a, b, c, d, e, f, g, h;
        static void 燃烧𠮷(对象𠮷 value) {
            long sum = result;
            for (int i = 0; i < 100_000; i++) sum = Long.rotateLeft(sum ^ i, 13) * 0x100000001b3L;
            result = sum + value.a;
        }
    }
    public static void main(String[] args) throws Exception {
        AsyncProfiler profiler = AsyncProfiler.getInstance(Paths.get(args[0]).toAbsolutePath().toString());
        Path output = Paths.get(args[1]);
        对象𠮷 monitor = new 对象𠮷();
        Thread holder = new Thread(() -> {
            try {
                while (!Thread.currentThread().isInterrupted()) {
                    synchronized (monitor) { Thread.sleep(10); }
                    Thread.sleep(1);
                }
            } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
        });
        holder.setDaemon(true);
        holder.start();
        for (int i = 0; i < 10_000; i++) 对象𠮷.燃烧𠮷(monitor);
        profiler.execute("start,event=cpu,interval=1000000,alloc=1024,lock=1,jfr,file=" + output);
        try {
            long end = System.nanoTime() + 2_000_000_000L;
            while (System.nanoTime() < end) {
                for (int i = 0; i < 1000; i++) retained = new 对象𠮷();
                for (int i = 0; i < 20; i++) 对象𠮷.燃烧𠮷(monitor);
                synchronized (monitor) { result++; }
            }
        } finally {
            profiler.stop();
            holder.interrupt();
            holder.join();
        }
        String collapsed = profiler.execute("collapsed,total");
        if (!collapsed.contains("UnicodeJvmSmoke$对象𠮷.燃烧𠮷")) throw new AssertionError("Unicode collapsed method was lost");
        Files.write(Paths.get(output + ".collapsed"), collapsed.getBytes(StandardCharsets.UTF_8));
        int methods = 0;
        int allocations = 0;
        int locks = 0;
        for (RecordedEvent event : RecordingFile.readAllEvents(output)) {
            String name = event.getEventType().getName();
            if (name.startsWith("jdk.ObjectAllocation") && event.getClass("objectClass").getName().equals("UnicodeJvmSmoke$对象𠮷")) allocations++;
            if (name.equals("jdk.JavaMonitorEnter") && event.getClass("monitorClass").getName().equals("UnicodeJvmSmoke$对象𠮷")) locks++;
            if (event.getStackTrace() == null) continue;
            for (RecordedFrame frame : event.getStackTrace().getFrames()) {
                RecordedMethod method = frame.getMethod();
                if (method.getType().getName().equals("UnicodeJvmSmoke$对象𠮷") && method.getName().equals("燃烧𠮷")) {
                    if (!method.getDescriptor().equals("(LUnicodeJvmSmoke$对象𠮷;)V")) throw new AssertionError("Unicode signature was lost: " + method.getDescriptor());
                    methods++;
                }
            }
        }
        if (methods == 0 || allocations == 0 || locks == 0) throw new AssertionError("Missing Unicode events: methods=" + methods + " allocations=" + allocations + " locks=" + locks);
        System.out.println("UNICODE_JVM_OK methods=" + methods + " allocations=" + allocations + " locks=" + locks);
    }
}
