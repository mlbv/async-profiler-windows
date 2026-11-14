/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */

package one.profiler.test;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Windows modules of the JVM under test whose PDBs a test needs: jvm.dll exports none of the internal functions
 * tests name or probe, and other modules' internal frames are named after the nearest export without their PDBs.
 */
public enum Pdb {
    JVM("server/jvm.dll", "server/jvm.dll"),
    JAVA("java.dll", "java.dll"),
    // Holds JavaMain
    LAUNCHER("java.exe", "jli.dll");

    private static final byte[] MSF_MAGIC = "Microsoft C/C++ MSF 7.00\r\n\u001aDS\0\0\0".getBytes(StandardCharsets.US_ASCII);

    private final String jdk8Image;
    private final String image;

    Pdb(String jdk8Image, String image) {
        this.jdk8Image = jdk8Image;
        this.image = image;
    }

    public File image(File javaHome, int jvmVersion) {
        return new File(javaHome, "bin/" + (jvmVersion <= 8 ? jdk8Image : image));
    }

    /**
     * Whether DbgHelp, searching as the profiler configures it, finds a PDB with the image's CodeView GUID and age:
     * at the CodeView path, or in the image's directory or a directory of ASYNC_PROFILER_SYMBOL_PATH.
     */
    public static boolean matched(File image) throws IOException {
        byte[] codeView = codeView(image);
        if (codeView == null) {
            return false;
        }
        byte[] guid = Arrays.copyOfRange(codeView, 4, 20);
        int age = ByteBuffer.wrap(codeView).order(ByteOrder.LITTLE_ENDIAN).getInt(20);
        String pdbPath = new String(codeView, 24, codeView.length - 24, StandardCharsets.UTF_8);
        pdbPath = pdbPath.substring(0, pdbPath.indexOf('\0'));
        String pdbName = pdbPath.substring(Math.max(pdbPath.lastIndexOf('\\'), pdbPath.lastIndexOf('/')) + 1);
        String extension = image.getName().substring(image.getName().lastIndexOf('.') + 1);

        List<File> directories = new ArrayList<>();
        directories.add(image.getParentFile());
        String symbolPath = System.getenv("ASYNC_PROFILER_SYMBOL_PATH");
        if (symbolPath != null) {
            for (String directory : symbolPath.split(";")) {
                if (!directory.isEmpty()) {
                    directories.add(new File(directory));
                }
            }
        }
        List<File> candidates = new ArrayList<>();
        if (new File(pdbPath).isAbsolute()) {
            candidates.add(new File(pdbPath));
        }
        for (File directory : directories) {
            candidates.add(new File(directory, pdbName));
            candidates.add(new File(directory, extension + '/' + pdbName));
            candidates.add(new File(directory, "symbols/" + extension + '/' + pdbName));
        }
        for (File candidate : candidates) {
            if (candidate.isFile() && pdbMatches(candidate, guid, age)) {
                return true;
            }
        }
        return false;
    }

    // RSDS record: signature, GUID, age, NUL-terminated PDB path; null if the image has none
    private static byte[] codeView(File image) throws IOException {
        try (RandomAccessFile file = new RandomAccessFile(image, "r")) {
            int pe = read(file, 0x3c, 4).getInt(0);
            // PE signature, COFF header, PE32+ optional header through the debug data directory
            ByteBuffer headers = read(file, pe, 24 + 112 + 7 * 8);
            int debugRva = headers.getInt(24 + 112 + 6 * 8);
            int debugSize = headers.getInt(24 + 112 + 6 * 8 + 4);
            if (debugSize == 0) {
                return null;
            }
            int sections = headers.getShort(6) & 0xffff;
            ByteBuffer sectionTable = read(file, pe + 24 + (headers.getShort(20) & 0xffff), sections * 40);
            long debugOffset = 0;
            for (int s = 0; s < sections * 40; s += 40) {
                int delta = debugRva - sectionTable.getInt(s + 12);
                if (delta >= 0 && delta < sectionTable.getInt(s + 8)) {
                    debugOffset = (sectionTable.getInt(s + 20) & 0xffffffffL) + delta;
                }
            }
            ByteBuffer debugDirectory = read(file, debugOffset, debugSize);
            for (int e = 0; e < debugSize; e += 28) {
                if (debugDirectory.getInt(e + 12) == 2) { // IMAGE_DEBUG_TYPE_CODEVIEW
                    ByteBuffer record = read(file, debugDirectory.getInt(e + 24) & 0xffffffffL, debugDirectory.getInt(e + 16));
                    if (record.getInt(0) == 0x53445352) { // RSDS
                        return record.array();
                    }
                }
            }
            return null;
        }
    }

    // GUID of the PDB info stream (1) and age of the DBI stream (3), which DbgHelp matches against CodeView
    private static boolean pdbMatches(File pdb, byte[] guid, int age) throws IOException {
        try (RandomAccessFile file = new RandomAccessFile(pdb, "r")) {
            ByteBuffer superBlock = read(file, 0, 56);
            if (!Arrays.equals(Arrays.copyOf(superBlock.array(), MSF_MAGIC.length), MSF_MAGIC)) {
                throw new IOException(pdb + " is not an MSF 7.00 PDB");
            }
            int blockSize = superBlock.getInt(32);
            int directoryBlocks = (int) ((superBlock.getInt(44) + (long) blockSize - 1) / blockSize);
            ByteBuffer blockMap = read(file, (long) superBlock.getInt(52) * blockSize, directoryBlocks * 4);
            byte[] directory = new byte[directoryBlocks * blockSize];
            for (int b = 0; b < directoryBlocks; b++) {
                file.seek((long) blockMap.getInt(b * 4) * blockSize);
                file.readFully(directory, b * blockSize, blockSize);
            }
            ByteBuffer streams = ByteBuffer.wrap(directory).order(ByteOrder.LITTLE_ENDIAN);
            byte[] pdbGuid = read(file, firstBlock(streams, 1, blockSize) * blockSize + 12, 16).array();
            int dbiAge = read(file, firstBlock(streams, 3, blockSize) * blockSize + 8, 4).getInt(0);
            return Arrays.equals(pdbGuid, guid) && dbiAge == age;
        }
    }

    // Directory: stream count, stream sizes (-1 for a nil stream), then each stream's block numbers
    private static long firstBlock(ByteBuffer directory, int stream, int blockSize) {
        long offset = 4 + 4L * directory.getInt(0);
        for (int s = 0; s < stream; s++) {
            int size = directory.getInt(4 + 4 * s);
            if (size != -1) {
                offset += 4 * (((size & 0xffffffffL) + blockSize - 1) / blockSize);
            }
        }
        return directory.getInt((int) offset) & 0xffffffffL;
    }

    private static ByteBuffer read(RandomAccessFile file, long offset, int length) throws IOException {
        byte[] bytes = new byte[length];
        file.seek(offset);
        file.readFully(bytes);
        return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
    }
}
