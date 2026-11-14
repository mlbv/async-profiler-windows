/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import jdk.jfr.consumer.RecordingFile;

public final class ReadEtw {
    public static void main(String[] args) throws Exception {
        var complete = 0;
        var workload = 0;
        var library = args.length == 1;
        var kernel = 0;
        var namedKernel = 0;
        var internalKernel = 0;
        for (var event : RecordingFile.readAllEvents(Path.of(args[0]))) {
            if (event.getEventType().getName().equals("jdk.NativeLibrary") && args.length > 1) {
                library |= event.getString("name").replace('\\', '/').equals(args[1].replace('\\', '/'));
            }
            if (!event.getEventType().getName().equals("jdk.ExecutionSample")) continue;
            var work = false;
            var caller = false;
            for (var frame : event.getStackTrace().getFrames()) {
                var name = frame.getMethod().getName();
                if (frame.getType().equals("Kernel")) {
                    kernel++;
                    if (name.contains("ntoskrnl.exe!") && !name.contains("+0x")) namedKernel++;
                    if (name.contains("ntoskrnl.exe!Exp") || name.contains("ntoskrnl.exe!Psp")) internalKernel++;
                }
                work |= name.contains("NativeCpuWork");
                caller |= name.contains("wmain");
            }
            if (work) workload++;
            if (work && caller) complete++;
        }
        if (complete == 0) throw new AssertionError("No ETW sample contains both the sampled workload and its caller");
        if (complete * 20 < workload * 19) throw new AssertionError("ETW native callers were lost: complete=" + complete + " workload=" + workload);
        if (!library) throw new AssertionError("Native library path was not preserved in the recording: " + args[1]);
        if (args.length > 2 && args[2].equals("kernel") && (kernel == 0 || namedKernel == 0 || internalKernel == 0)) throw new AssertionError("Missing PDB kernel frames: kernel=" + kernel + " named=" + namedKernel + " internal=" + internalKernel);
        if (args.length > 2 && args[2].equals("kernel-raw") && (kernel == 0 || namedKernel != 0)) throw new AssertionError("Kernel restriction was not preserved: kernel=" + kernel + " named=" + namedKernel);
        System.out.println("etwCompleteNativeStacks=" + complete);
        System.out.println("kernelFrames=" + kernel + " namedKernelFrames=" + namedKernel + " internalKernelFrames=" + internalKernel);
    }
}
