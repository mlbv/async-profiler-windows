/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

package test.cstack;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;

public class LongInitializer {
    private static final boolean WINDOWS = System.getProperty("os.name").startsWith("Windows");

    static class InnerClass {
        static {
            byte[] bytes = new byte[16];
            byte[] empty = new byte[16];
            try (FileInputStream fis = new FileInputStream(WINDOWS ? randomFile() : "/dev/urandom")) {
                long count = 0;
                while (read(fis, bytes) > 0 && !Arrays.equals(bytes, empty)) {
                    count++;
                }
                System.out.println("You are lucky! " + count);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    // Windows has no /dev/urandom: a file of random bytes stands in, read again from its start at the end
    private static String randomFile() throws IOException {
        Path file = Paths.get(System.getProperty("java.io.tmpdir"), "async-profiler-test-random");
        if (!Files.exists(file)) {
            byte[] random = new byte[1 << 20];
            new SecureRandom().nextBytes(random);
            Path partial = Files.write(Files.createTempFile(file.getParent(), null, null), random);
            try {
                Files.move(partial, file);
            } catch (FileAlreadyExistsException e) {
                Files.delete(partial);
            }
        }
        return file.toString();
    }

    private static int read(FileInputStream fis, byte[] bytes) throws IOException {
        int n = fis.read(bytes);
        if (n < 0 && WINDOWS) {
            fis.getChannel().position(0);
            n = fis.read(bytes);
        }
        return n;
    }

    public static void main(String[] args) throws Exception {
        Class.forName(InnerClass.class.getName());
    }
}
