/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

package test.smoke;

import one.profiler.test.Os;
import one.profiler.test.Output;
import one.profiler.test.Pdb;
import one.profiler.test.Test;
import one.profiler.test.TestProcess;

public class SmokeTests {

    @Test(mainClass = Cpu.class)
    public void cpu(TestProcess p) throws Exception {
        Output out = p.profile("-d 3 -e cpu -o collapsed");
        assert out.contains("test/smoke/Cpu.main;test/smoke/Cpu.method1");
        assert out.contains("test/smoke/Cpu.main;test/smoke/Cpu.method2");
        assert out.contains("test/smoke/Cpu.main;test/smoke/Cpu.method3;java/io/File");
    }

    @Test(mainClass = Alloc.class, pdb = Pdb.JVM, pdbJvmVer = 8)
    public void alloc(TestProcess p) throws Exception {
        Output out = p.profile("-d 3 -e alloc -o collapsed -t");
        assert out.contains("\\[AllocThread-1 tid=[0-9]+];.*Alloc.allocate;.*java.lang.Integer\\[]");
        assert out.contains("\\[AllocThread-2 tid=[0-9]+];.*Alloc.allocate;.*int\\[]");
    }

    @Test(mainClass = Threads.class, agentArgs = "start,event=cpu,collapsed,threads,file=%f")
    public void threads(TestProcess p) throws Exception {
        Output out = p.waitForExit("%f");
        assert out.contains("\\[ThreadEarlyEnd tid=[0-9]+];.*Threads.methodForThreadEarlyEnd;.*");
        assert out.contains("\\[RenamedThread tid=[0-9]+];.*Threads.methodForRenamedThread;.*");
    }

    // Thread-name filters also cover the Windows CPU engine.
    @Test(mainClass = Threads.class, os = Os.WINDOWS, nameSuffix = "cpu",
            agentArgs = "start,event=cpu,ithread=ThreadWillBe*,collapsed,file=%f")
    @Test(mainClass = Threads.class,
            agentArgs = "start,event=wall,ithread=ThreadWillBe*,collapsed,file=%f")
    public void threadNameFilter(TestProcess p) throws Exception {
        Output out = p.waitForExit("%f");
        assert out.contains("Threads.methodForRenamedThread");
        assert !out.contains("Threads.methodForThreadEarlyEnd");
    }

    @Test(mainClass = Threads.class, os = Os.WINDOWS, nameSuffix = "cpu",
            agentArgs = "start,event=cpu,xthread=ThreadWillBe*,collapsed,file=%f")
    @Test(mainClass = Threads.class,
            agentArgs = "start,event=wall,xthread=ThreadWillBe*,collapsed,file=%f")
    public void threadNameFilterExclude(TestProcess p) throws Exception {
        Output out = p.waitForExit("%f");
        assert !out.contains("Threads.methodForRenamedThread");
        assert out.contains("Threads.methodForThreadEarlyEnd");
    }

    @Test(mainClass = Threads.class, os = Os.WINDOWS, nameSuffix = "cpu",
            agentArgs = "start,event=cpu,ithread=Thread*,xthread=ThreadWillBe*,collapsed,file=%f")
    @Test(mainClass = Threads.class,
            agentArgs = "start,event=wall,ithread=Thread*,xthread=ThreadWillBe*,collapsed,file=%f")
    public void threadNameFilterIncludeExclude(TestProcess p) throws Exception {
        Output out = p.waitForExit("%f");
        assert out.contains("Threads.methodForThreadEarlyEnd");
        assert !out.contains("Threads.methodForRenamedThread");
    }

    @Test(mainClass = LoadLibrary.class, os = {Os.LINUX, Os.MACOS})
    @Test(mainClass = LoadLibraryWindows.class, os = Os.WINDOWS, nameSuffix = "windows")
    public void loadLibrary(TestProcess p) throws Exception {
        p.profile("-f %f -o collapsed -d 4 -i 1ms");
        Output out = p.readFile("%f");
        assert out.contains(p.currentOs() == Os.WINDOWS ? "Java_test_stackwalker_StackGenerator_leafFrame;doCpuTask" : "Java_sun_management");
    }
}
