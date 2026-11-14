/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import jdk.jfr.consumer.RecordingFile;

public final class ReadStackDepth {
    public static void main(String[] args) throws Exception {
        var limit = Integer.parseInt(args[1]);
        var retained = Integer.parseInt(args[2]);
        var javaOnly = Boolean.parseBoolean(args[3]);
        var physical = Boolean.parseBoolean(args[4]);
        var complete = 0;
        var bounded = 0;
        var maximumJava = 0;
        var maximumInline = 0;
        var partial = 0;
        for (var event : RecordingFile.readAllEvents(Path.of(args[0]))) {
            if (!event.getEventType().getName().equals("jdk.ExecutionSample")) continue;
            var java = 0;
            var inlined = 0;
            var payload = 0;
            var truncated = 0;
            var first = false;
            var last = false;
            var incomplete = false;
            for (var frame : event.getStackTrace().getFrames()) {
                var method = frame.getMethod();
                var name = method.getName();
                var type = frame.getType();
                if (name.equals("truncated")) truncated++;
                incomplete |= name.startsWith("etw_") && name.endsWith("_unwind_incomplete");
                var nativeFrame = type.equals("Native") || type.equals("Kernel");
                if (!nativeFrame) java++;
                if (javaOnly && nativeFrame && !name.equals("truncated") && !name.equals("no_Java_frame")
                        && !name.startsWith("etw_")) throw new AssertionError("Native frame leaked: " + name);
                if (!method.getType().getName().equals("DeepStackPayload")) continue;
                payload++;
                if (type.equals("Inlined")) inlined++;
                first |= name.equals("m0");
                last |= name.equals("m519");
            }
            // Explicitly incomplete traces end early, so requested depth limits do
            // not apply to them; the physical case checks its capture ceiling instead.
            if (incomplete && !physical) { partial++; continue; }
            if (retained == 0 && truncated != 0) {
                if (java != 0 || truncated != 1) throw new AssertionError("Invalid zero-depth trace: java=" + java + " markers=" + truncated);
                bounded++;
            }
            if (payload == 0) continue;
            maximumJava = Math.max(maximumJava, java);
            maximumInline = Math.max(maximumInline, inlined);
            if (physical) {
                if (!last) continue;
                if (truncated != 1) throw new AssertionError("Physical capture ceiling was not marked: " + truncated);
                bounded++;
            } else if (limit == 1024) {
                if (payload == 520 && first && last && inlined >= 514) complete++;
            } else {
                if (retained < limit && truncated == 0) {
                    if (java >= limit) throw new AssertionError("Missing truncation marker: java=" + java);
                } else {
                    if (java > retained) throw new AssertionError("Depth limit ignored: java=" + java + " retained=" + retained);
                    if (truncated > 1) throw new AssertionError("Duplicate truncation marker: " + truncated);
                    if (java == retained) bounded++;
                }
            }
        }
        if (!physical && limit == 1024 && complete < 10) throw new AssertionError("Lost expanded inline callers: complete=" + complete
                + " maximumJava=" + maximumJava + " maximumInline=" + maximumInline);
        if (limit != 1024 && bounded < 10) throw new AssertionError("Missing bounded workload stacks: " + bounded);
        if (physical && (bounded < 10 || maximumJava >= 520)) throw new AssertionError("Physical ceiling fixture did not exercise truncation");
        System.out.println("STACK_DEPTH_OK limit=" + limit + " retained=" + retained + " javaOnly=" + javaOnly
                + " complete=" + complete + " bounded=" + bounded + " partial=" + partial + " maximumJava=" + maximumJava + " maximumInline=" + maximumInline);
    }
}
