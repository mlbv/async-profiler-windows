/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordedFrame;
import jdk.jfr.consumer.RecordedMethod;
import jdk.jfr.consumer.RecordingFile;

public final class ReadVmStacks {
    public static void main(String[] args) throws Exception {
        int busySamples = 0;
        int intrinsicSamples = 0;
        Set<String> frameTypes = new HashSet<>();
        for (RecordedEvent event : RecordingFile.readAllEvents(Paths.get(args[0]))) {
            if (!event.getEventType().getName().equals("jdk.ExecutionSample") || event.getStackTrace() == null) continue;
            boolean busy = false;
            boolean main = false;
            boolean intrinsic = false;
            for (RecordedFrame frame : event.getStackTrace().getFrames()) {
                RecordedMethod method = frame.getMethod();
                boolean fixture = method.getType().getName().equals("Fixture");
                if (fixture) frameTypes.add(frame.getType());
                busy |= fixture && method.getName().equals("busy");
                main |= fixture && method.getName().equals("main");
                intrinsic |= method.getName().contains("IntrinsicStubsGen.fmod");
            }
            if (busy) busySamples++;
            if (intrinsic) intrinsicSamples++;
            if ((busy || intrinsic) && !main || intrinsic && !busy) throw new AssertionError("Lost workload callers: " + event);
        }
        if (busySamples == 0) throw new AssertionError("No complete workload stacks");
        if (args[1].equals("interpreter") && !frameTypes.equals(Collections.singleton("Interpreted"))) throw new AssertionError("Wrong interpreter frame types: " + frameTypes);
        if (args[1].equals("c1") && !frameTypes.contains("C1 compiled")) throw new AssertionError("Missing C1 frame classification: " + frameTypes);
        System.out.println("completeBusyStacks=" + busySamples + " intrinsicStacks=" + intrinsicSamples + " frameTypes=" + frameTypes);
    }
}
