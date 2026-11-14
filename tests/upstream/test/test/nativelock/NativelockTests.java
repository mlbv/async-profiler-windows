/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

package test.nativelock;

import one.profiler.test.Os;
import one.profiler.test.Output;
import one.profiler.test.Test;
import one.profiler.test.TestProcess;

public class NativelockTests {

    // Windows stacks end at the lock's caller, without a hook frame. Each fixture function takes one
    // lock kind: a critical section (mutex), or an SRW lock in shared (rdlock) or exclusive (wrlock) mode.
    private static String lockFrame(TestProcess p, String hook, String windowsCaller) {
        return p.currentOs() == Os.WINDOWS ? ";" + windowsCaller + " " : hook;
    }

    private static String mutex(TestProcess p) {
        return lockFrame(p, "pthread_mutex_lock_hook", "Java_test_nativelock_NativeLock_mutexContentionThread");
    }

    private static String rdlock(TestProcess p) {
        return lockFrame(p, "pthread_rwlock_rdlock_hook", "Java_test_nativelock_NativeLock_rdlockContentionThread");
    }

    private static String wrlock(TestProcess p) {
        return lockFrame(p, "pthread_rwlock_wrlock_hook", "Java_test_nativelock_NativeLock_wrlockContentionThread");
    }

    @Test(mainClass = AllNativeLocks.class)
    public void canAsprofTraceAllLockTypes(TestProcess p) throws Exception {
        Output out = p.profile("-e nativelock -d 3 -o collapsed");
        assert out.contains(mutex(p)) : "No mutex samples captured";
        assert out.contains(rdlock(p)) : "No rdlock samples captured";
        assert out.contains(wrlock(p)) : "No wrlock samples captured";
    }

    @Test(mainClass = AllNativeLocks.class, agentArgs = "start,nativelock,collapsed,file=%f", args = "once")
    public void canAgentTraceAllLockTypes(TestProcess p) throws Exception {
        Output out = p.waitForExit("%f");
        assert out.contains(mutex(p)) : "No mutex samples captured in agent mode";
        assert out.contains(rdlock(p)) : "No rdlock samples captured in agent mode";
        assert out.contains(wrlock(p)) : "No wrlock samples captured in agent mode";
    }

    @Test(mainClass = AllNativeLocks.class, os = {Os.LINUX, Os.WINDOWS}, args = "once", env = { "LD_PRELOAD=%lib", "ASPROF_COMMAND=start,nativelock,file=%f.jfr" })
    public void ldpreloadAllLockTypes(TestProcess p) throws Exception {
        p.waitForExit();
        Output out = Output.convertJfrToCollapsed(p.getFilePath("%f"), "--nativelock");
        assert out.contains(mutex(p)) : "No mutex samples captured with LD_PRELOAD";
        assert out.contains(rdlock(p)) : "No rdlock samples captured with LD_PRELOAD";
        assert out.contains(wrlock(p)) : "No wrlock samples captured with LD_PRELOAD";
    }

    @Test(sh = "LD_PRELOAD=%lib ASPROF_COMMAND=start,nativelock,file=%f.jfr %testbin/native_lock_contention", os = {Os.LINUX, Os.WINDOWS}, runIsolated = true)
    public void nativeAllLockContention(TestProcess p) throws Exception {
        p.waitForExit();
        Output out = Output.convertJfrToCollapsed(p.getFilePath("%f"), "--nativelock");
        assert out.contains(lockFrame(p, "pthread_mutex_lock_hook", "mutex_contention_thread")) : "No mutex samples captured in pure native test";
        assert out.contains(lockFrame(p, "pthread_rwlock_rdlock_hook", "rwlock_reader_thread")) : "No rdlock samples captured in pure native test";
        assert out.contains(lockFrame(p, "pthread_rwlock_wrlock_hook", "rwlock_writer_thread")) : "No wrlock samples captured in pure native test";
    }
}
