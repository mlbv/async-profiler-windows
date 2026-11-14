/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

package test.comptask;

import one.profiler.test.*;

public class ComptaskTests {
    @Test(
        mainClass = Main.class,
        agentArgs = "start,features=comptask,collapsed,interval=1ms,file=%f",
        jvmArgs = "-Xcomp",
        jvm = Jvm.HOTSPOT_C2,
        pdb = Pdb.JVM
    )
    public void testCompTask(TestProcess p) throws Exception {
        Output out = p.waitForExit("%f");
        assert p.exitCode() == 0;
        assert out.contains(";Compiler::compile_method;(java|sun|jdk)/[^;]+[^;/]\\.[^;/]+;");
        assert out.contains(";C2Compiler::compile_method;(java|sun|jdk)/[^;]+[^;/]\\.[^;/]+;");
    }
}
