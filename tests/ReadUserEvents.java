/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import jdk.jfr.consumer.RecordingFile;

public final class ReadUserEvents {
    public static void main(String[] args) throws Exception {
        var lengths = new ArrayList<Integer>();
        for (var event : RecordingFile.readAllEvents(Path.of(args[0]))) {
            if (!event.getEventType().getName().equals("profiler.UserEvent")) continue;
            var type = event.getString("type");
            if (!type.equals("fixture.事件")) throw new AssertionError("Wrong UTF-8 user-event name: " + type);
            if (event.getThread() == null) throw new AssertionError("Missing user-event thread");
            var data = event.getString("data");
            lengths.add(data.length());
            for (var i = 0; i < data.length(); i++) if (data.charAt(i) != (char)(i & 255)) throw new AssertionError("Binary payload changed");
        }
        Collections.sort(lengths);
        System.out.println("payloadLengths=" + lengths);
        if (!lengths.equals(java.util.List.of(0, 256, 2048))) throw new AssertionError("Missing or unexpected user events");
    }
}
