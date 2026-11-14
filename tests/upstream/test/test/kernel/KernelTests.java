/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

package test.kernel;

import one.profiler.test.Output;
import one.profiler.test.Test;
import one.profiler.test.TestProcess;
import one.profiler.test.Os;

import java.io.IOException;

public class KernelTests {

    // Windows lists a directory through NtQueryDirectoryFile(Ex), entered from ntdll's system call stub
    private static String getdents(TestProcess p) {
        return p.currentOs() == Os.WINDOWS ? "ZwQueryDirectoryFile(Ex)?;.*NtQueryDirectoryFile" : "(sys|SyS)_getdents";
    }

    private static String symbolsUnavailable(TestProcess p) {
        return p.currentOs() == Os.WINDOWS ? "Windows kernel symbols are unavailable" : "Kernel symbols are unavailable";
    }

    @Test(mainClass = ListFiles.class, os = {Os.LINUX, Os.WINDOWS}, etw = true)
    public void kernel(TestProcess p) throws Exception {
        Output out = p.profile("-e cpu-clock -d 3 -i 1ms -o collapsed");
        Output err = p.readFile(TestProcess.PROFERR);
        assert out.contains("test/kernel/ListFiles.listFiles;java/io/File");
        assert err.contains(symbolsUnavailable(p)) || out.contains(getdents(p));

        out = p.profile("stop -o flamegraph");
        out = out.convertFlameToCollapsed();
        assert out.contains("java/io/File.list");
        assert err.contains(symbolsUnavailable(p)) || out.contains(getdents(p));
    }

    @Test(mainClass = ListFiles.class, os = {Os.LINUX, Os.WINDOWS}, etw = true)
    public void fdtransfer(TestProcess p) throws Exception {
        p.profile("-e cpu -d 3 -i 1ms -o collapsed -f %f --fdtransfer", true);
        Output out = p.readFile("%f");
        assert out.contains("test/kernel/ListFiles.listFiles;java/io/File");
        assert out.contains(getdents(p));
    }

    // Windows: N/A, user mode has no kernel function probe facility
    @Test(mainClass = ListFiles.class, os = Os.LINUX)
    public void kprobe(TestProcess p) throws Exception {
        p.profile("-e kprobe:fd_install -d 2 -o collapsed -f %f --fdtransfer", true);
        Output out = p.readFile("%f");
        assert out.contains("java/io/File.list;.+;fd_install_\\[k]");
    }

    // Windows: N/A, fdtransfer is the port's ETW broker
    @Test(mainClass = ListFiles.class, os = Os.MACOS)
    public void notLinux(TestProcess p) throws Exception {
        try {
            p.profile("-e cpu -d 3 -i 1ms -o collapsed -f %f --fdtransfer");
            throw new AssertionError("FdTransferClient should succeed on Linux only");
        } catch (IOException e) {
            assert p.readFile(TestProcess.PROFERR).contains("Failed to initialize FdTransferClient");
        }
    }
}
