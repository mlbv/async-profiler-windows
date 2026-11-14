/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

package test.cstack;

import one.profiler.test.Jvm;
import one.profiler.test.Os;
import one.profiler.test.Output;
import one.profiler.test.Pdb;
import one.profiler.test.Test;
import one.profiler.test.TestProcess;
import test.smoke.Cpu;

public class CstackTests {
    private static final String PROFILE_COMMAND = "-e cpu -i 10ms -d 1 -o collapsed -a ";

    @Test(mainClass = LongInitializer.class, pdb = Pdb.JAVA)
    public void asyncGetCallTrace(TestProcess p) throws Exception {
        // Windows walks Java stacks through VM structures unless AsyncGetCallTrace is requested
        String agct = p.currentOs() == Os.WINDOWS ? "-F agct " : "";
        Output out = p.profile(PROFILE_COMMAND + agct + "--cstack no");
        assert !out.contains(";readBytes") : out;
        assert out.contains("LongInitializer.main_\\[j]") : out;

        // Windows x64 code keeps no frame pointer chain; its native unwind data is cstack=dwarf
        out = p.profile(PROFILE_COMMAND + agct + (p.currentOs() == Os.WINDOWS ? "--cstack dwarf" : "--cstack fp"));
        assert out.contains(";readBytes") : out;
        assert out.contains("LongInitializer.main_\\[j]") : out;
    }

    @Test(mainClass = LongInitializer.class, jvm = Jvm.HOTSPOT, os = {Os.LINUX, Os.WINDOWS}, pdb = {Pdb.JVM, Pdb.LAUNCHER})
    public void vmStructs(TestProcess p) throws Exception {
        Output out = p.profile(PROFILE_COMMAND + "--cstack vm");
        assert out.contains(";readBytes");
        assert out.contains("LongInitializer.main_\\[0]");
        assert !out.contains("InstanceKlass::initialize");
        assert !out.contains("call_stub");
        assert !out.contains("JavaMain");

        out = p.profile(PROFILE_COMMAND + "--cstack vmx");
        assert out.contains(";readBytes");
        assert out.contains("LongInitializer.main_\\[0]");
        assert out.contains("InstanceKlass::initialize");
        assert out.contains("call_stub");
        assert out.contains("JavaMain");
    }

    @Test(mainClass = Cpu.class, jvm = Jvm.HOTSPOT, agentArgs = "start,event=cpu,interval=1ms", pdb = {Pdb.JVM, Pdb.JAVA})
    public void saneNativeStack(TestProcess p) throws Exception {
        Thread.sleep(2000);
        Output out = p.profile("stop -o flamegraph").convertFlameToCollapsed();

        assert out.contains("^test/smoke/Cpu.main");
        assert out.contains("CompileBroker::");
        assert out.contains("Java_java_io_");

        // No JVM frames before start_thread
        assert !out.contains("CompileBroker::.*;start_thread");

        // No duplicated native frames
        assert !out.contains("Java_java_io_.*;Java_java_io_");
    }
}
