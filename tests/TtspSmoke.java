/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Files;
import java.nio.file.Path;
import one.profiler.AsyncProfiler;

public final class TtspSmoke {
    public static void main(String[] args) throws Exception {
        var profiler = AsyncProfiler.getInstance(Path.of(args[0]).toAbsolutePath().toString());
        var options = args[2].equals("nostop") ? ",nostop" : "";
        profiler.execute("start,event=cpu,interval=1ms,cstack=vm,ttsp" + options + ",jfr,file=" + args[1]);
        try { test.jfr.Ttsp.main(new String[0]); }
        finally { profiler.stop(); }
        Files.writeString(Path.of(args[1] + ".collapsed"), profiler.execute("collapsed,total"));
        System.out.println(profiler.execute("metrics"));
    }
}
