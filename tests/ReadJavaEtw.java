/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import jdk.jfr.consumer.RecordingFile;

public final class ReadJavaEtw {
    public static void main(String[] args) throws Exception {
        var java = 0;
        var lines = 0;
        var inlined = 0;
        var incomplete = 0;
        var unicode = 0;
        var c1 = 0;
        var vmIncomplete = 0;
        var nativeIncomplete = 0;
        var interpreter = 0;
        var physicalChains = 0;
        var completeJavaChains = 0;
        var interpretedJava = 0;
        var nativeRoots = 0;
        var samples = 0;
        var cpuFrames = 0;
        var pcFrames = 0;
        var adapterSamples = 0;
        var completeAdapters = 0;
        var compiledAdapters = 0;
        var scalarLeafSamples = 0;
        var scalarLineSamples = 0;
        var completeScalar = 0;
        var unprovenLeafSamples = 0;
        var unprovenLineSamples = 0;
        var cutLeafSamples = 0;
        var target = args.length > 1 ? args[1] : "EtwJavaSmoke";
        var mode = args.length > 2 ? args[2] : "plain";
        var interpreted = mode.equals("interpreted") || mode.equals("java-only-interpreted");
        var javaOnly = mode.startsWith("java-only");
        var recordCpu = mode.equals("java-only-cpu-id");
        var requireC1 = mode.equals("c1");
        var features = args.length > 3 ? args[3] : "";
        var pcAddress = features.contains("pcaddr");
        for (var event : RecordingFile.readAllEvents(Path.of(args[0]))) {
            if (!event.getEventType().getName().equals("jdk.ExecutionSample")) continue;
            samples++;
            var names = new HashSet<String>();
            var nativeRoot = false;
            var partial = false;
            var adapterFrame = false;
            var truncatedFrame = false;
            var scalarLeaf = false;
            var scalarLine = false;
            var unprovenLeaf = false;
            var unprovenLine = false;
            var framesBeyondUnproven = false;
            var frameIndex = 0;
            for (var frame : event.getStackTrace().getFrames()) {
                var method = frame.getMethod();
                if (unprovenLeaf && !method.getName().equals("truncated") && !method.getName().equals("etw_stack_incomplete")
                        && !method.getName().endsWith("_unwind_incomplete")) framesBeyondUnproven = true;
                var sampledPc = pcAddress && frameIndex == 0 && method.getName().matches("[0-9a-fA-F]{16}(?:_\\[k\\])?");
                var physicalLeaf = frameIndex++ == (pcAddress ? 1 : 0);
                if (sampledPc) pcFrames++;
                if (method.getName().startsWith("CPU-")) cpuFrames++;
                nativeRoot |= method.getName().equals("RtlUserThreadStart") || method.getName().equals("LdrInitializeThunk");
                adapterFrame |= physicalLeaf && method.getName().equals("I2C/C2I adapters");
                truncatedFrame |= method.getName().equals("truncated");
                if (method.getName().equals("etw_java_unwind_incomplete")) incomplete++;
                if (method.getName().equals("etw_vm_unwind_incomplete")) vmIncomplete++;
                if (method.getName().equals("etw_native_unwind_incomplete")) nativeIncomplete++;
                partial |= method.getName().equals("etw_stack_incomplete") || method.getName().endsWith("_unwind_incomplete")
                        || method.getName().equals("truncated");
                if (method.getName().equals("Interpreter")) interpreter++;
                if (method.getName().equals("stale_jmethodID")) throw new AssertionError("Stale Java metadata");
                if (javaOnly && (frame.getType().equals("Native") || frame.getType().equals("Kernel"))) {
                    var name = method.getName();
                    if (!sampledPc && !(recordCpu && name.startsWith("CPU-")) && !name.equals("no_Java_frame") && !name.equals("truncated")
                            && !name.equals("etw_stack_incomplete") && !name.equals("etw_java_unwind_incomplete")
                            && !name.equals("etw_vm_unwind_incomplete") && !name.equals("etw_native_unwind_incomplete")) {
                        throw new AssertionError("Native frame leaked into cstack=no: " + name);
                    }
                }
                if (frame.getType().equals("Inlined")) inlined++;
                if (!method.getType().getName().equals(target)) continue;
                names.add(method.getName());
                if (!frame.getType().equals("JIT compiled") && !frame.getType().equals("Inlined") && !frame.getType().equals("C1 compiled")
                        && !frame.getType().equals("Interpreted")) throw new AssertionError("Java method reported as " + frame.getType());
                java++;
                if (frame.getType().equals("Interpreted")) interpretedJava++;
                if (method.getName().equals("adapterTarget") && !frame.getType().equals("Interpreted")) compiledAdapters++;
                if (frame.getType().equals("C1 compiled")) c1++;
                if (method.getName().equals("燃烧𠮷")) unicode++;
                var validLine = frame.getLineNumber() > 0 && frame.getBytecodeIndex() >= 0 && frame.getBytecodeIndex() < 65536;
                if (validLine) lines++;
                if (physicalLeaf && frame.getType().equals("JIT compiled")) {
                    if (method.getName().equals("unprovenTarget")) { scalarLeaf = true; scalarLine = validLine; }
                    if (method.getName().equals("unprovenFmaTarget")) { unprovenLeaf = true; unprovenLine = validLine; }
                }
            }
            if (names.containsAll(Set.of("燃烧𠮷", "middle", "outer"))) physicalChains++;
            if (names.containsAll(Set.of("燃烧𠮷", "middle", "outer", "work", "main"))) completeJavaChains++;
            if (nativeRoot) nativeRoots++;
            if (adapterFrame && "main".equals(event.getThread("sampledThread").getJavaName())) {
                adapterSamples++;
                if (nativeRoot && !partial && names.contains("adapters")) completeAdapters++;
            }
            var mainThread = "main".equals(event.getThread("sampledThread").getJavaName());
            if (mode.equals("scalar") && scalarLeaf && mainThread) {
                scalarLeafSamples++;
                if (scalarLine) scalarLineSamples++;
                if (nativeRoot && !partial && names.containsAll(Set.of("unprovenTarget", "unprovenWork", "record", "main")))
                    completeScalar++;
            }
            if (mode.equals("unproven") && unprovenLeaf && mainThread) {
                unprovenLeafSamples++;
                if (unprovenLine) unprovenLineSamples++;
                if (partial && truncatedFrame) {
                    if (framesBeyondUnproven || nativeRoot || names.size() != 1 || !names.contains("unprovenFmaTarget"))
                        throw new AssertionError("Unproven FMA leaf retained callers beyond its CFI boundary: " + names);
                    cutLeafSamples++;
                }
            }
            if (!javaOnly && !mode.equals("cpu") && !nativeRoot && !partial) {
                throw new AssertionError("Unmarked incomplete native stack");
            }
        }
        if (mode.equals("adapters")) {
            if (compiledAdapters == 0 || interpretedJava == 0 || adapterSamples == 0 || completeAdapters != adapterSamples) {
                throw new AssertionError("Missing complete interpreter-to-compiled transitions: compiled=" + compiledAdapters
                        + " interpreted=" + interpretedJava + " adapters=" + adapterSamples + " complete=" + completeAdapters);
            }
        } else if (mode.equals("scalar")) {
            if (scalarLeafSamples == 0 || scalarLineSamples == 0 || (long)completeScalar * 100 < (long)scalarLeafSamples * 95)
                throw new AssertionError("Scalar compiled callers were not recovered: leaves=" + scalarLeafSamples
                        + " lineSamples=" + scalarLineSamples + " complete=" + completeScalar);
        } else if (mode.equals("unproven")) {
            if (unprovenLeafSamples == 0 || unprovenLineSamples == 0 || cutLeafSamples == 0)
                throw new AssertionError("Missing explicitly cut compiled FMA leaves: leaves=" + unprovenLeafSamples
                        + " lineSamples=" + unprovenLineSamples + " cuts=" + cutLeafSamples);
        } else if (interpreted) {
            if (interpretedJava == 0 || completeJavaChains == 0 || unicode == 0 || lines == 0) {
                throw new AssertionError("Missing interpreted Java chain: interpreted=" + interpretedJava + " complete=" + completeJavaChains);
            }
        } else {
            if (java == 0 || lines == 0) throw new AssertionError("Missing Java metadata: java=" + java + " lines=" + lines);
            if (target.equals("EtwJavaSmoke") && unicode == 0) throw new AssertionError("Supplementary Unicode method name was lost");
            if (target.equals("EtwJavaSmoke") && physicalChains == 0) throw new AssertionError("Physical Java callers were not recovered");
            if (requireC1 && c1 == 0) throw new AssertionError("C1 compilation type was lost");
        }
        if (javaOnly && completeJavaChains == 0) throw new AssertionError("cstack=no lost Java callers");
        if (recordCpu && cpuFrames != samples) throw new AssertionError("Lost CPU IDs: " + cpuFrames + " samples=" + samples);
        if (pcAddress && pcFrames != samples) throw new AssertionError("Exact PC did not prefix every sample: " + pcFrames + " samples=" + samples);
        if (!javaOnly && !mode.equals("cpu") && !mode.equals("unproven") && (long)nativeRoots * 100 < (long)samples * (interpreted || mode.equals("exceptions") ? 99 : 95)) {
            throw new AssertionError("Native caller roots were lost: roots=" + nativeRoots + " samples=" + samples);
        }
        System.out.println("javaFrames=" + java + " lineFrames=" + lines + " inlined=" + inlined + " c1=" + c1 + " physicalChains=" + physicalChains
                + " completeJavaChains=" + completeJavaChains + " interpretedJava=" + interpretedJava
                + " nativeRoots=" + nativeRoots
                + " cpuFrames=" + cpuFrames
                + " pcFrames=" + pcFrames
                + " adapterSamples=" + adapterSamples + " completeAdapters=" + completeAdapters + " compiledAdapters=" + compiledAdapters
                + " scalarLeafSamples=" + scalarLeafSamples + " scalarLineSamples=" + scalarLineSamples + " completeScalar=" + completeScalar
                + " unprovenLeafSamples=" + unprovenLeafSamples + " unprovenLineSamples=" + unprovenLineSamples
                + " cutLeafSamples=" + cutLeafSamples
                + " incomplete=" + incomplete + " vmIncomplete=" + vmIncomplete + " nativeIncomplete=" + nativeIncomplete
                + " interpreter=" + interpreter);
    }
}
