/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

package one.profiler;

import jdk.jfr.Configuration;
import jdk.jfr.FlightRecorder;
import jdk.jfr.FlightRecorderListener;
import jdk.jfr.Recording;
import jdk.jfr.RecordingState;

import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.channels.FileChannel;
import java.text.ParseException;
import java.util.StringTokenizer;
import java.util.concurrent.locks.LockSupport;

/**
 * Synchronize async-profiler recording with an existing JFR recording.
 */
class JfrSync implements FlightRecorderListener {
    // Keep in sync with EventCategory
    private static final int EC_CPU        = 0;
    private static final int EC_ALLOC      = 1;
    private static final int EC_LOCK       = 2;
    private static final int EC_CATEGORIES = 8;

    // Keep in sync with JfrOption
    private static final int NO_SYSTEM_INFO  = 1;
    private static final int NO_SYSTEM_PROPS = 2;
    private static final int NO_NATIVE_LIBS  = 4;
    private static final int NO_CPU_LOAD     = 8;
    private static final int NO_HEAP_SUMMARY = 16;

    private static volatile Recording masterRecording;
    private static Path masterDestination;
    private static Path masterStagingFile;

    private JfrSync() {
    }

    static {
        FlightRecorder.addListener(new JfrSync());
    }

    @Override
    public void recordingStateChanged(Recording recording) {
        if (recording == masterRecording && recording.getState() == RecordingState.STOPPED) {
            stopProfiler();
        }
    }

    public static void start(String fileName, String settings, int eventMask, boolean staged) throws IOException, ParseException {
        Recording recording;
        if (settings.startsWith("+")) {
            recording = new Recording();
            for (StringTokenizer st = new StringTokenizer(settings, "+"); st.hasMoreTokens(); ) {
                enableEvent(recording, st.nextToken());
            }
        } else {
            try {
                recording = new Recording(Configuration.getConfiguration(settings));
            } catch (NoSuchFileException e) {
                recording = new Recording(Configuration.create(Paths.get(settings)));
            }
            disableBuiltinEvents(recording, eventMask);
        }

        masterDestination = staged ? Paths.get(fileName) : null;
        masterStagingFile = null;
        try {
            if (staged) masterStagingFile = Files.createTempFile("asprof-jvm-", ".jfr");
            recording.setDestination(staged ? masterStagingFile : Paths.get(fileName));
            recording.setToDisk(true);
            recording.setDumpOnExit(true);
            masterRecording = recording;
            recording.start();
        } catch (IOException | RuntimeException e) {
            masterRecording = null;
            recording.close();
            if (masterStagingFile != null) Files.deleteIfExists(masterStagingFile);
            masterStagingFile = masterDestination = null;
            throw e;
        }
    }

    private static void enableEvent(Recording recording, String event) {
        int separator = event.indexOf('#');
        if (separator < 0) {
            recording.enable(event);
            return;
        }

        int eq = event.indexOf('=', separator + 1);
        String setting = eq >= 0 ? event.substring(separator + 1, eq) : event.substring(separator + 1);
        String value = eq >= 0 ? event.substring(eq + 1) : "";
        recording.enable(event.substring(0, separator)).with(setting, value);
    }

    public static boolean stop() throws IOException {
        Recording recording = masterRecording;
        if (recording != null) {
            // Disable state change notification before stopping
            masterRecording = null;
            boolean complete = false;
            try {
                try {
                    if (recording.getState() == RecordingState.RUNNING) recording.stop();
                    else if (recording.getState() == RecordingState.STOPPED && masterStagingFile != null) recording.dump(masterStagingFile);
                } catch (IllegalStateException e) {
                    // The shutdown hook can finish writing outside the state lock.
                    for (int pause = 10; recording.getState() != RecordingState.CLOSED && pause < 1000; pause *= 2) {
                        LockSupport.parkNanos(pause * 1_000_000L);
                    }
                    if (recording.getState() != RecordingState.CLOSED) return false;
                }
                if (masterStagingFile != null) append(masterStagingFile, masterDestination);
                complete = true;
            } finally {
                recording.close();
                if (masterStagingFile != null) {
                    if (complete) Files.deleteIfExists(masterStagingFile);
                    else System.err.println("JVM recording data retained at " + masterStagingFile);
                }
                masterStagingFile = masterDestination = null;
            }
        }
        return true;
    }

    public static void appendSnapshot(String filename) throws IOException {
        Recording recording = masterRecording;
        if (recording == null || recording.getState() != RecordingState.RUNNING) {
            throw new IllegalStateException("Synchronized JFR recording is not running");
        }
        java.nio.file.Path snapshot = Files.createTempFile("asprof-jvm-", ".jfr");
        try {
            recording.dump(snapshot);
            append(snapshot, Paths.get(filename));
        } finally {
            Files.deleteIfExists(snapshot);
        }
    }

    private static void append(Path input, Path output) throws IOException {
        try (FileChannel source = FileChannel.open(input, StandardOpenOption.READ);
             FileChannel destination = FileChannel.open(output, StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
            long offset = 0;
            while (offset < source.size()) {
                long copied = source.transferTo(offset, source.size() - offset, destination);
                if (copied == 0) throw new IOException("Cannot append JVM recording data");
                offset += copied;
            }
        }
    }

    private static void disableBuiltinEvents(Recording recording, int eventMask) {
        if ((eventMask & (1 << EC_CPU)) != 0) {
            recording.disable("jdk.ExecutionSample");
            recording.disable("jdk.NativeMethodSample");
        }
        if ((eventMask & (1 << EC_ALLOC)) != 0) {
            recording.disable("jdk.ObjectAllocationInNewTLAB");
            recording.disable("jdk.ObjectAllocationOutsideTLAB");
            recording.disable("jdk.ObjectAllocationSample");
            recording.disable("jdk.OldObjectSample");
        }
        if ((eventMask & (1 << EC_LOCK)) != 0) {
            recording.disable("jdk.JavaMonitorEnter");
            recording.disable("jdk.ThreadPark");
        }
        // No need to disable jdk.MethodTrace, and no built-in events correspond to other event categories

        eventMask >>>= EC_CATEGORIES;
        // Shifted JfrOption values
        if ((eventMask & NO_SYSTEM_INFO) != 0) {
            recording.disable("jdk.OSInformation");
            recording.disable("jdk.CPUInformation");
            recording.disable("jdk.JVMInformation");
        }
        if ((eventMask & NO_SYSTEM_PROPS) != 0) {
            recording.disable("jdk.InitialSystemProperty");
        }
        if ((eventMask & NO_NATIVE_LIBS) != 0) {
            recording.disable("jdk.NativeLibrary");
        }
        if ((eventMask & NO_CPU_LOAD) != 0) {
            recording.disable("jdk.CPULoad");
        }
        if ((eventMask & NO_HEAP_SUMMARY) != 0) {
            recording.disable("jdk.GCHeapSummary");
        }
    }

    private static native void stopProfiler();

    // JNI helper
    static Integer box(int n) {
        return n;
    }
}
