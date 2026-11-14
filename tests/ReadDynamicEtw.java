/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import jdk.jfr.consumer.RecordingFile;

public final class ReadDynamicEtw {
    public static void main(String[] args) throws Exception {
        var begin = Long.parseUnsignedLong(args[1], 16);
        var end = begin + Long.parseLong(args[2]);
        var marker = Long.parseUnsignedLong(args[3], 16);
        var metadata = Boolean.parseBoolean(args[4]);
        var generated = 0;
        var complete = 0;
        var marked = 0;
        var maximumMetadataDepth = 0;
        var expectedDepth = args.length > 5 ? Integer.parseInt(args[5]) : 1;
        for (var event : RecordingFile.readAllEvents(Path.of(args[0]))) {
            if (!event.getEventType().getName().equals("jdk.ExecutionSample")) continue;
            var code = false;
            var caller = false;
            var root = false;
            var hasMarker = false;
            var depth = 0;
            for (var frame : event.getStackTrace().getFrames()) {
                var name = frame.getMethod().getName();
                try {
                    var pc = Long.parseUnsignedLong(name, 16);
                    code |= pc >= begin && pc < end;
                    hasMarker |= pc == marker;
                    if (pc == marker) depth++;
                } catch (NumberFormatException ignored) { }
                caller |= name.contains("NativeDynamicWork");
                root |= name.equals("wmain");
            }
            if (!code) continue;
            generated++;
            if (caller && root) complete++;
            if (hasMarker) marked++;
            maximumMetadataDepth = Math.max(maximumMetadataDepth, depth);
        }
        if (generated == 0 || complete != generated || metadata && maximumMetadataDepth < expectedDepth) throw new AssertionError("Generated unwind mismatch: samples=" + generated + " complete=" + complete + " metadataDepth=" + maximumMetadataDepth);
        System.out.println("DYNAMIC_ETW_OK generated=" + generated + " complete=" + complete + " metadata=" + marked + " metadataDepth=" + maximumMetadataDepth);
    }
}
