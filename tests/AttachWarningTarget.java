/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
/** Waits for the CLI to attach, then exits when standard input closes. */
public final class AttachWarningTarget {
    public static void main(String[] args) throws Exception {
        System.out.println("READY");
        System.out.flush();
        while (System.in.read() >= 0) { }
    }
}
