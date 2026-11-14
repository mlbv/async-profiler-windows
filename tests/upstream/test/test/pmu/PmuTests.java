/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

package test.pmu;

import one.profiler.test.Arch;
import one.profiler.test.Output;

import java.io.IOException;

import one.profiler.test.Assert;
import one.profiler.test.Test;
import one.profiler.test.TestProcess;
import one.profiler.test.Os;

public class PmuTests {

    // Run alone: concurrent PMC captures must select the same machine-wide ETW overflow source
    @Test(mainClass = Dictionary.class, os = {Os.LINUX, Os.WINDOWS}, runIsolated = true, etw = true)
    public void cycles(TestProcess p) throws Exception {
        try {
            p.profile("-e ref-cycles -d 3 -o collapsed -f %f");
            Output out = p.readFile("%f");
            // We are skipping the test in one case, for more details: https://github.com/actions/runner-images/issues/11689
            if (out.total() == 0 &&
                    System.getProperty("os.arch").contains("aarch64") &&
                    "true".equals(System.getenv("GITHUB_ACTIONS"))) {
                System.out.println("Skipping the test PmuTests.cycles on ARM64 in GitHub Actions as no samples have been collected");
                return;
            }

            Assert.isGreater(out.ratio("test/pmu/Dictionary.test16K"), 0.4);
            Assert.isGreater(out.ratio("test/pmu/Dictionary.test8M"), 0.4);
        } catch (Exception e) {
            if (!pmuUnavailable(p)) {
                throw e;
            }
        }
    }

    // Run alone: concurrent PMC captures must select the same machine-wide ETW overflow source
    @Test(mainClass = Dictionary.class, os = {Os.LINUX, Os.WINDOWS}, arch = {Arch.X64, Arch.X86}, runIsolated = true, etw = true)
    public void cacheMisses(TestProcess p) throws Exception {
        try {
            p.profile("-e cache-misses -d 3 -o collapsed -f %f");

            // TODO: https://github.com/async-profiler/async-profiler/issues/1588
            //  It was observed on certain system configuration that the 'cache-misses' event will not be collected,
            //  both async-profiler & perf are failing to collect samples & reporting 0 with no obvious cause,
            //  the test is marked as pass if such a condition is encountered until that is root caused
            if (p.getFile("%f").length() != 0) {
                Output out = p.readFile("%f");
                Assert.isLess(out.ratio("test/pmu/Dictionary.test16K"), 0.2);
                Assert.isGreater(out.ratio("test/pmu/Dictionary.test8M"), 0.8);
            }
        } catch (Exception e) {
            if (!pmuUnavailable(p)) {
                throw e;
            }
        }
    }

    // Windows words the same conditions as an unavailable ETW source or a missing profiling privilege
    private static boolean pmuUnavailable(TestProcess p) {
        Output err = p.readFile(TestProcess.PROFERR);
        return err.contains("Perf events unavailable") || p.currentOs() == Os.WINDOWS &&
                err.contains("ETW profile source is unavailable|ETW capture requires SeSystemProfilePrivilege");
    }

    @Test(mainClass = Dictionary.class, os = Os.MACOS)
    public void pmuIncompatible(TestProcess p) throws Exception {
        try {
            p.profile("-e cache-misses -d 3 -o collapsed -f %f");
            throw new AssertionError("PerfEvents should succeed on Linux only");
        } catch (IOException e) {
            assert p.readFile(TestProcess.PROFERR).contains("PerfEvents are not supported on this platform");
        }
    }
}
