/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Files;
import java.nio.file.Path;
import one.profiler.AsyncProfiler;
import test.recovery.Numbers;
import test.recovery.Suppliers;

public final class VtableSmoke {
    public static void main(String[] args) throws Exception {
        var profiler = AsyncProfiler.getInstance(Path.of(args[0]).toAbsolutePath().toString());
        var mode = args[2];
        var worker = new Thread(() -> {
            if (mode.equals("vtable")) Numbers.main(new String[0]);
            else Suppliers.main(new String[0]);
        }, "upstream-" + mode);
        worker.setDaemon(true);
        worker.start();
        Thread.sleep(1000);
        profiler.execute("start,event=cpu,interval=1ms,cstack=vm,features=vtable,filter");
        profiler.addThread(worker);
        try { Thread.sleep(5000); }
        finally { profiler.stop(); }
        var collapsed = profiler.execute("collapsed,total");
        Files.writeString(Path.of(args[1]), collapsed);
        System.out.println(profiler.execute("metrics"));
        if (mode.equals("vtable")) {
            if (!collapsed.contains("vtable stub;java.lang.Integer_[i]")
                    || !collapsed.contains("vtable stub;java.lang.Long_[i]")) {
                throw new AssertionError("Missing upstream Integer/Long vtable receiver frames");
            }
        } else if (!java.util.regex.Pattern.compile("itable stub;test\\.recovery\\.Suppliers[^_;]+_\\[i]").matcher(collapsed).find()) {
            throw new AssertionError("Missing upstream supplier itable receiver frames");
        }
        System.out.println("UPSTREAM_RECEIVERS_OK " + mode);
    }
}
