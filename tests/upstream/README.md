# Upstream test suite on Windows

`test/` is async-profiler's own test tree at the revision in `UPSTREAM`: the Java runner (`test/one/profiler/test`), the `@Test` cases in `test/test`, their native programs and libraries, and the C++ unit tests in `test/native`. Windows adaptations are small edits beside the upstream code (`Os.WINDOWS` branches, `_WIN32` blocks, `*_windows.c` variants); Windows-only support code is in `windows/`. Each semantic adaptation carries a comment where it is made and is listed below.

## Running

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests/upstream/run.ps1 -JdkHome C:/jdk-25 -BuildJdk C:/jdk-25 `
  -SymbolPath 'C:/jdk-25-debug-image/bin;C:/jdk-25-debug-image/bin/server'
```

`run.ps1` mirrors upstream's `make test`. It needs the port's build (`build.ps1`) and then:

- builds `build/jar/async-profiler.jar` and `build/jar/jfr-converter.jar` from `core/src`, and `build/test.jar` from `test/` with `-source 8 -target 8`;
- downloads the declared dependency `protobuf-java` into `test/deps` (`test/gen` holds upstream's generated OpenTelemetry classes);
- configures the port's CMake tree with `ASPROF_UPSTREAM_TESTS=ON` and builds the target `upstream-tests` (`CMakeLists.txt`, `windows/cpptests.cmake`) with the port's Clang/MinGW toolchain: test libraries in `build/test/lib`, test programs in `build/test/bin`, C++ unit tests in `build/test/cpptests.exe`;
- runs the C++ unit tests when no `-Tests` filter is given, then `one.profiler.test.Runner` on `-JdkHome` from this directory, against `build/asyncProfiler.dll` and `build/asprof.exe`.

Options follow upstream's variables: `-Tests` (`TESTS`; test directories, classes, methods or `*` globs, comma-separated), `-Skip`, `-Threads` (default 8), `-RetryCount`, `-LogDir` (default `build/test/logs`), `-LogLevel`. `-BuildJdk` (17+) compiles the JARs; `-NoBuild` reuses the previous build.

Prerequisites beyond the port's build:

- Git for Windows: `sh.exe` runs the `sh` tests.
- The JDK's PDBs through `-SymbolPath` (`ASYNC_PROFILER_SYMBOL_PATH`): `jvm.dll`'s and those of its native libraries, such as `java.dll`; on JDK 8 they are under `jre/bin`. Temurin 8's debug image lacks `java.exe`'s PDB (`java.exe` and `java.dll` both name theirs `java.pdb`; the image ships `java.dll`'s), so `JavaMain` stays unnamed there. Without `java.dll`'s, its internal helpers are named after the nearest export, which CstackTests.saneNativeStack reports as duplicated native frames. Upstream relies on libjvm's symbol table; `jvm.dll` exports none of the internal functions that tests name or probe (`G1CollectedHeap::humongous_obj_allocate`, `SafepointSynchronize::begin`, `C2Compiler::compile_method`, `JavaCalls::call_helper`, `JavaMain`, ...), and without them the profiler prints `Install JVM debug symbols`, which also breaks tests that parse its output. Temurin publishes debug images with PDBs; GraalVM and Azul publish none, and tests that need them skip there.
- For kernel frame names, the running kernel's PDBs (`ntkrnlmp.pdb` and the file-system drivers') in `-SymbolPath`, as upstream needs kallsyms; `symchk` from the Debugging Tools for Windows fetches them.
- Elevation for ETW cases (record-cpu/target-cpu, PMU events, kernel stacks), as upstream CI runs them as root: run the suite from an elevated shell; `sudo` cases fail when the runner is not elevated.
- An otherwise idle machine for the timing-sensitive cases (CPU/wall shares, durations).

## Harness adaptations

- `Runner`: GraalVM detection looks for `jvmcicompiler.dll` in `bin/` (JDK 8: `jre/bin`).
- `TestProcess`: the profiler is `../../build/asyncProfiler.dll`; `profile()` runs `build/asprof.exe` with upstream's arguments; `sh` tests use Git for Windows `sh` and get temporary paths with forward slashes (backslashes would be escapes there and in the path substitution); `LD_PRELOAD` (environment or inline in `sh`) becomes `asprof-helper.exe --preload LIB ... -- COMMAND`, keeping `ASPROF_COMMAND`; `sudo` requires an elevated runner (High or System integrity); on JDK 8, child PIDs come from `GetProcessId` through `windows/processid.c`.
- `Test.pdb`/`pdbJvmVer`/`jfr` and `SKIP_ENVIRONMENT`: on Windows, a test that needs a JVM module's PDB names the module (`jvm.dll`; `java.dll`; the launcher, which holds `JavaMain`: `jli.dll`, on JDK 8 `java.exe`), optionally only on some JVM versions, and skips with "needs PDBs for MODULE" unless DbgHelp would load a PDB matching the module's CodeView GUID and age from the module's directory, its CodeView path or a `-SymbolPath` directory. A `jfr` test skips with "needs JFR" when the JVM under test has no `jdk.jfr` Flight Recorder. Each skip prints its reason; the summary counts them as `SKIP (environment)`.
- `Test.etw`: JVMs of tests whose Java stacks the profiler captures through ETW (KernelTests, PmuTests, the `perfEvents*` CpuTests, JfrTests.recordCpuMultiEngine) start with `-XX:+UnlockDiagnosticVMOptions -XX:+WhiteBoxAPI`, and on GraalVM EE 8 also `-XX:-UseJVMCINativeLibrary`. ETW unwind records for compiled code must lie within 32-bit RVAs of the code cache, where other reservations, on GraalVM libgraal's 32 GiB compiler isolates, can leave no room. The repository README's launch-time workaround for code-cache unwind records is a VM-owned WhiteBox buffer, which the profiler never enables on attach. GraalVM EE 8's WhiteBox has no such buffer, so it runs the Graal compiler as jargraal, which reserves no isolates; on the newer GraalVMs jargraal's startup compilation burst slows the first capture's stop (7.7 s against 0.5 s) past the 10 s profile timeout.
- `Output`: converter text is split on its `\n` separator rather than `System.lineSeparator()`.
- Native programs use `windows/include/dlfcn.h` (LoadLibrary/GetProcAddress) and load the profiler from `../../build/asyncProfiler.dll`; `non_java_app` loads `jvm.dll` from `bin/server`. `build/test/lib` is on `PATH` for the libraries' own DLL imports (upstream: `LD_LIBRARY_PATH`).
- The UCRT has no `posix_memalign` or `aligned_alloc`; `jnimalloc` imports them from `windows/alignedalloc.c`, which serves the tests' 16-byte alignment from `malloc`, so upstream's `free()` releases the blocks.
- Native mutexes and reader/writer locks are critical sections and SRW locks (`jninativelocks_windows.c`, `native_lock_contention_windows.c`), the primitives the port's `nativelock` traces. Windows lock stacks end at the lock's caller rather than a hook frame, so lock kinds are identified by the fixture function that takes each lock.
- The runner's temporary directory, and test processes' `TEMP`/`TMP`, is `build/test/tmp`. Ending a test process or a timed-out `asprof` call also ends its descendants (`sh`'s commands, the launcher's target), except `asprof-helper.exe`, whose session watchers and broker outlive their target to end its ETW session.
- PmuTests.cycles and cacheMisses run in the isolated phase: concurrent PMC captures must select the same machine-wide ETW overflow source, and the two select different ones. `basicProcessSampling` runs alone too, because its command-line filter also matches a concurrent `BasicApp` test.

## Test inventory

Upstream v4.6 declares 172 active Java `@Test` cases, of which 33 name Linux in their OS restriction. This copy declares 183 active cases, including Windows-specific alternatives, four additional CPU thread-filter variants and the sleep-transition regression. Eleven commented-out process tests are excluded from both counts; OS, JVM version and prerequisite checks determine which run. The removed upstream datagram-lock test is no longer included. The API, converters and all Java test sources compile with Java 8 bytecode targeting on GraalVM 25.2.4+7.1. Targeted v4.6 verification on JDK 27 passes 58 unique Java cases across three runs: the initial selection passed 39, with four missing-PDB and two platform skips; the symbol-enabled stack-walker selection passed seven, with one platform skip; the new-feature selection passed all 18 without skips. The latter covers three symbol-dependent allocation cases, two JFR event-setting cases, six CPU/wall thread-name filter variants, the rate limiter and all six converter cases. All 80 native unit cases pass, including rate-limit parsing and maximum-rate carryover. The legacy feature selection passes 17/17 on each of JDK 8, 11 and 21. The rate-limit test with harness-owned workload lifetime passes on JDK 8/11/21/27, each 1/1 without skips. The elevated 15-JVM v4.6 gate has completed; its results and unresolved cases are recorded below. Other runtime evidence and known failures below come from the v4.5 gate unless stated otherwise.

Status values: **as-is**, **adapted** (what changed), **N/A** (why), **fails** (port defect or limitation, see Known failures). *PDB: MODULE* marks a test that skips without that PDB, *JFR* one that skips without `jdk.jfr` (see Harness adaptations); GraalVM EE 8 has only Oracle's commercial Flight Recorder, so its `jdk.jfr.consumer` tests also skip as missing JARs. "elevated" marks tests that need an elevated runner.

| Test | Windows status |
| --- | --- |
| AllocTests.alloc | as-is; PDB: `jvm.dll` |
| AllocTests.allocTotal | as-is; PDB on JDK 8: `jvm.dll` |
| AllocTests.startup | Windows variant `startup/windows`: `cstack=vmx`. The JVM's Windows x64 code keeps no frame-pointer chain, and `cstack=dwarf` becomes the VM walker, which (as upstream) records no native frames for allocation samples; PDB on JDK 8: `jvm.dll` |
| AllocTests.humongous | enabled (Linux-only upstream): JVM-function probe; PDB: `jvm.dll` |
| AllocTests.tlabAllocSampler | as-is, including v4.6 allocation class, outside-TLAB, stack integrity and caller-ratio assertions; PDB: `jvm.dll` (TLAB breakpoints) |
| AllocTests.objectSamplerWtihDifferentAsprofs | as-is |
| AllocTests.liveness (4), livenessJfrHasStacks (4) | as-is |
| ApiTests.flat, javaAgent | as-is |
| ApiTests.otlp, stopResume | as-is |
| ApiTests.threadFilter (2) | wall API add/remove plus a Windows CPU variant; verifies included and excluded threads |
| ApiTests.metrics | adapted: `NUL` for `/dev/null`; the port's `events_dropped_total` and `windows_*` metrics may be zero |
| CTests.nativeApi (2) | adapted: Windows build of `native_api` |
| ComptaskTests.testCompTask | as-is (C2 JVMs); PDB: `jvm.dll` |
| CpuTests.itimerTotal | as-is |
| CpuTests.ctimerTotal | enabled |
| CpuTests.perfEventsTargetCpuEventsCount, perfEventsRecordCpuEventsCount | enabled; CPU pinning through the process affinity mask; elevated |
| CpuTests.perfEventsTargetCpuWithFdtransferEventsCount | enabled; elevated |
| CpuTests.{itimer,ctimer}DoesNotSupport{TargetCpu,RecordCpu} (4) | enabled |
| CstackTests.asyncGetCallTrace | adapted: `-F agct`, since Windows walks Java stacks through VM structures by default; `--cstack dwarf` (PE unwind data) for the native half, since Windows x64 code keeps no frame-pointer chain; `LongInitializer` re-reads a file of random bytes in place of `/dev/urandom`; PDB: `java.dll` (`readBytes`) |
| CstackTests.vmStructs | enabled; PDB: `jvm.dll`, launcher |
| CstackTests.saneNativeStack | as-is; PDB: `jvm.dll`, `java.dll` |
| DepthTests.maxDepth | as-is |
| InstrumentTests (24) | as-is; `latencyJfr` adapted: also accepts `method = null`, which the JFR consumer of Oracle JDK 11 based runtimes (GraalVM EE 11) prints for the unset field |
| JfrTests.cpuLoad, parseRecording, allModeEventOverride | as-is |
| JfrTests.jfrSyncSmoke | as-is; JFR |
| JfrTests.parseMultiModeRecording (2), ttsp, ttspNostop | as-is; separate JDK 8 multimode settings; PDB: `jvm.dll` |
| JfrTests.jfrSyncEventSettings (2) | as-is; JFR; exception event with default settings and explicit stack traces |
| JfrTests.rateLimit | adapted: workers run until `TestProcess.close()` ends the target, so symbol-loading/attach overhead cannot exhaust a fixed workload lifetime; the four-second capture, CPU/allocation/span budgets and assertions are unchanged. PDB on JDK 8: `jvm.dll`; passes on JDK 8/11/21/27, each 1/1 without skips |
| JfrTests.recordCpuMultiEngine | enabled; elevated |
| JfrTests.allModeNoEventOverride (2) | adapted: all mode records CPU samples on Windows, as on Linux |
| JfrTests.beginEnd | Windows variant `beginEnd/windows`: `ucrtbase.dll!_write`; POSIX `write` is the UCRT's `_write`, and a bare name exported by several modules is rejected as ambiguous |
| JfrTests.clockSource (2) | adapted: Windows' monotonic clock is QueryPerformanceCounter, not 1 GHz; JFR |
| JfrconverterTests.heatmapConversion, flamegraphConversion | adapted: `NUL` for `/dev/null` |
| JfrconverterTests.latencyFilter, tagFilter, diffCollapsed, diffHtml | as-is; span latency and regex tag filters |
| KernelTests.kernel | enabled: `NtQueryDirectoryFile(Ex)` below ntdll's system call stub, the port's kernel-symbol warning; kernel PDBs; elevated |
| KernelTests.fdtransfer | enabled, as `kernel`; kernel PDBs; elevated |
| KernelTests.kprobe | N/A: user mode has no kernel function probe facility |
| KernelTests.notLinux | N/A: `--fdtransfer` is the port's ETW broker |
| NativelockTests.canAsprofTraceAllLockTypes, canAgentTraceAllLockTypes | adapted: Windows lock fixture and caller frames |
| NativelockTests.ldpreloadAllLockTypes, nativeAllLockContention | enabled through the preload launcher |
| NativememTests.canAgentTraceMallocCalloc (2), canAgentFilterMallocCalloc, canAsprofTraceMallocCalloc, canAgentTraceRealloc, canAsprofTraceRealloc, canAsprofTraceAllNoLeak, jfrNoLeaks (5), jfrNoFree (2) | as-is (aligned allocation from the test provider); the `multi` variants need PDB on JDK 8: `jvm.dll` |
| NativememTests.dlopenCustomLib (dlopen_first, profile_first) | adapted: Windows build of `profile_with_dlopen` |
| NativememTests.dlopenCustomLib (+LD_PRELOAD, 2), malloc_plt_dyn, ldpreload | enabled through the preload launcher. Windows stacks end at the allocation's caller, so `ldpreload` looks for `Java_test_nativemem_Native_malloc` as the leaf rather than a `malloc_hook` frame; `ldpreload` needs PDB: launcher |
| NativememTests.preloadMalloc (3) | Windows variants through the preload launcher: `libmalloc.dll` (`malloc_windows.c`) replaces the program's `malloc` import, since imports bind per module rather than to a process-wide symbol; `preload_malloc` loads the profiler from the port's build |
| NativememTests.nativememKnownLibCrash | adapted: Windows build of the program |
| NonjavaTests.jvmFirst, profilerFirst, differentThread | adapted: Windows build of `non_java_app`; direct loaded-module JVM exports avoid transient Toolhelp snapshot failures during initialization |
| NonjavaTests.jvmInBetween | adapted as above |
| OtlpTests.sampleType, sampleTypeTotal | as-is |
| OtlpTests (other 8) | as-is |
| OtlpTests.serviceNameFromSystemProperty, serviceNameFromResourceAttributes, serviceNameFromResourceAttributesEnv | as-is; resource attributes, percent decoding and property/environment precedence |
| PmuTests.cycles, cacheMisses | enabled; an unavailable ETW source or missing profiling privilege counts as upstream's unavailable perf events; elevated |
| PmuTests.pmuIncompatible | macOS only |
| ProcTests.basicProcessSampling, processSamplingRequiresJfr, processSamplingWithCpuThreshold, processSamplingWithMemoryThreshold | enabled |
| ProcTests.processSamplingNotSupportedOnMacOS | macOS only |
| ProcTests (11 others) | commented out upstream; excluded from active test counts |
| RecoveryTests.stringBuilder, numbers, suppliers, intrinsics, currentTimeMillis | as-is; JIT cost attribution can miss numerical thresholds, including `numbers` on Azul 11 C2 (see Known failures) |
| RecoveryTests.stringBuilderArm | ARM only |
| SmokeTests.cpu, alloc, threads | as-is; `alloc` needs PDB on JDK 8: `jvm.dll` |
| SmokeTests.threadNameFilter, threadNameFilterExclude, threadNameFilterIncludeExclude (2 each) | upstream wall tests plus Windows CPU variants; creation-time names remain selected after a rename until the next refresh |
| SmokeTests.loadLibrary | Windows variant `loadLibrary/windows`: `management.dll`'s JNI getters tail-jump into `jvm.dll` and leave no frame, so `LoadLibraryWindows` loads the test library `jninativestacks` late and the test looks for its JNI frame |
| SpanTests.spans, api, attach | enabled |
| StackwalkerTests.largeFrame (2), deepStack (2), normalStackVM, largeInnerFrameVM | as-is |
| StackwalkerTests.normalStackVMX | adapted: HotSpot on Windows enters Java calls through `JavaCalls::call` and `os::os_exception_wrapper`; PDB: `jvm.dll`, launcher |
| StackwalkerTests.debugFrame | N/A: PE images keep unwind data in `.pdata`/`.xdata`, not DWARF `.debug_frame` |
| VmstructsTests.jnienv, jnienvAgent | adapted: wait for a fixture marker after both allocation workers execute before measuring; the harness waits through `WatchService`, and capture duration and assertions are unchanged. JFR (`-XX:StartFlightRecording`) |
| VmstructsTests.checkJni, checkHotCodeHeap | as-is |
| VtableTests.vtableStubs, itableStubs | as-is |
| WallTests.cpuWall | adapted: Windows loopback TCP leaves the reading client about a quarter of the CPU time (independently measured), so its share threshold is 0.15; bind an OS-assigned port and pass it directly to both clients |
| WallTests.flushBufferedSleepingSamples | as-is |
| WallTests.sleepTransitions | Windows regression: three distinct sleep callers separated by brief CPU work must retain their independently measured wall weights; validates high-resolution CPU baselines and cached-stack invalidation |

C++ unit tests (`test/native`):

| Test | Windows status |
| --- | --- |
| protobufBufferTest, demangleTest, nativeLockTest, safeAccessTest | as-is |
| argumentsTest | adapted: all mode enables CPU and process sampling on Windows, as on Linux; v4.6 per-category rate limits and malformed-list rejection retained |
| rateLimitTest | Windows regression: a maximum signed-int rate with a full refill retains a positive two-second burst budget |
| instrumentTest | enabled (Linux-only upstream, which needs the single-unit build); latencies use the port's 64-bit `Latency` |
| processInfoTest | enabled: the port implements process sampling; PID 4 replaces init; process times count 100 ns units |
| symbolsTest | N/A: ELF import, relocation and layout cases; the port intercepts PE imports through its own rules and never fills CodeCache import slots |
| perfEventsLinuxTest | N/A: Linux perf_events |

## Prerequisite skips by JVM

In the v4.5 gate, with each Temurin's debug-image PDBs on `-SymbolPath`, Temurin 11 to 27 skipped nothing for missing prerequisites. The v4.6 additions use the same prerequisite checks; `jfrSyncEventSettings` also requires JFR, and `rateLimit` requires `jvm.dll` PDBs on JDK 8. The historical skips were:

| JVM | Skipped tests (reason) |
| --- | --- |
| Temurin 8 | CstackTests.vmStructs, NativememTests.ldpreload, StackwalkerTests.normalStackVMX (PDBs for `java.exe`) |
| GraalVM 25, 21, 17, EE 11 | AllocTests.alloc, humongous, tlabAllocSampler, JfrTests.parseMultiModeRecording, ttsp, ttspNostop (PDBs for `jvm.dll`); CstackTests.asyncGetCallTrace (`java.dll`); CstackTests.saneNativeStack (`jvm.dll`, `java.dll`); CstackTests.vmStructs, StackwalkerTests.normalStackVMX (`jvm.dll`, `jli.dll`); NativememTests.ldpreload (`jli.dll`) |
| Azul 17, 11 | as GraalVM 25, plus ComptaskTests.testCompTask (`jvm.dll`) |
| GraalVM EE 8 | AllocTests.alloc, allocTotal, humongous, startup/windows, tlabAllocSampler, CstackTests.saneNativeStack, JfrTests.parseMultiModeRecording, ttsp, ttspNostop, NativememTests.jfrNoLeaks/multi, jfrNoFree/multi, SmokeTests.alloc (PDBs for `jvm.dll`); CstackTests.vmStructs, StackwalkerTests.normalStackVMX (`jvm.dll`, `java.exe`); NativememTests.ldpreload (`java.exe`); JfrTests.clockSource (2), jfrSyncSmoke, VmstructsTests.jnienv, jnienvAgent (JFR); 11 `jdk.jfr.consumer` tests as missing JARs |

## v4.6 full gate

The post-fix full gate ran elevated on port commit `fe12d86`, including wall-batching fix `9d15655` and fixture-readiness/port fix `3e0cf49`, with two runner threads, matching JVM/kernel PDBs and a machine-local mutex around live ETW tests. Each JVM evaluated 183 Java test variants and passed all 80 native unit cases. The following is the complete matrix; passes from later focused checks do not replace these full-run results.

| JVM | Java pass | Java fail | Platform skips | Missing JAR | Missing PDB/JFR |
| --- | ---: | ---: | ---: | ---: | ---: |
| Temurin 27 | 170 | 0 | 13 | 0 | 0 |
| Temurin 26 | 169 | 0 | 14 | 0 | 0 |
| Temurin 25 | 169 | 0 | 14 | 0 | 0 |
| Temurin 21 | 169 | 0 | 14 | 0 | 0 |
| Temurin 17 | 169 | 0 | 14 | 0 | 0 |
| Temurin 11 | 168 | 0 | 15 | 0 | 0 |
| Temurin 8 | 155 | 0 | 25 | 0 | 3 |
| GraalVM 25.2.4 | 155 | 0 | 17 | 0 | 11 |
| GraalVM 25.0.1 | 155 | 0 | 17 | 0 | 11 |
| GraalVM 21 | 154 | 1 | 17 | 0 | 11 |
| GraalVM 17 | 154 | 1 | 17 | 0 | 11 |
| GraalVM EE 11 | 153 | 1 | 18 | 0 | 11 |
| GraalVM EE 8 | 121 | 0 | 28 | 11 | 23 |
| Azul 17 | 157 | 0 | 14 | 0 | 12 |
| Azul 11 | 155 | 1 | 15 | 0 | 12 |

- **Wall-clock batch attribution, fixed.** The failed tag-filter recordings contained all three SDK spans, but one cached stack covered 21–23 samples across later calls. The Windows sampler now reads high-resolution thread CPU time while the target is suspended and omits the Linux EINTR shortcut, whose syscall fingerprint cannot distinguish successive Windows waits. The unchanged tag-filter tests pass on Temurin 8/17/26/27, GraalVM 17 and GraalVM EE 11. On the same six JVMs, the new three-phase sleep-transition regression verifies each caller's weight against independent elapsed times. The final DLL also passes the 17-thread cadence/weight checks in batched and unbatched modes.
- **Workload readiness, fixed.** The JNI-environment agent tests could stop while the JVM was still starting JFR, before allocation workers executed. Both tests now await a fixture marker written after both workers execute their first allocation; existing duration and frame assertions remain. All applicable cases pass in the post-fix full matrix.
- **TODO: unclassified allocation timeouts.** `AllocTests.objectSamplerWtihDifferentAsprofs` and `tlabAllocSampler` timed out on Temurin 25. A focused concurrent run passed both with complete symbols; a later private diagnostic overlay passed all fourteen applicable allocation cases without invoking its timeout stack capture. Capture native target and profiler-client stacks before timeout cleanup on the next occurrence; no timeout increase or assertion change is justified.
- **TODO: vtable coverage.** `VtableTests.vtableStubs` missed the Integer-specific stub frame on Temurin 17 while recording other stub types and `Integer.doubleValue`. The focused case passes; the original compiler/call-site behavior remains under investigation.
- **Socket fixture collision:** `WallTests.cpuWall` on GraalVM 25.0.1 exited with `BindException` on fixed port 1234. The fixture now binds port zero and passes its bound port to both clients; the unchanged profiling assertions pass in the focused check.
- **JIT cost attribution:** `RecoveryTests.numbers` fails on GraalVM 21 (0.446), GraalVM EE 11 (0.417) and Azul 11 (0.464) at its 0.5 inlined-`avg` threshold. Targeted Azul 11 C2 code/metadata capture confirms that the heavily sampled PCs in the volatile-store and safepoint-poll instruction sequences resolve to `loop@7`, while PCs inside the inlined average resolve to `avg@27 → loop@1`. The profiler follows those scopes; a low ratio is not by itself a missing-frame defect.
- **Native-application JVM initialization, fixed.** GraalVM 17 `NonjavaTests.jvmFirst` exited before sampling with `Could not find Thread ID field. Unsupported JVM?`. Two injected `ERROR_BAD_LENGTH` snapshot failures during global JVM-export lookup reproduce that error and the retained partial-initialization state. Windows now resolves the core exports directly from the loaded `jvm.dll`. The permanent `attachSnapshotTest` regression retains the fault hook, requires successful attachment and Java workload frames, and passes. A follow-up of all four Nonjava initialization orders plus `SmokeTests.threads` passes 5/5 on every one of the 15 runtimes (75/75); this is separate from the full-run table above. A pre-existing TODO remains for transactional cleanup if another initialization step fails.
- **TODO: intermittent failures from the first full run.** Temurin 8 `AllocTests.startup/windows` captured only two compiler-thread allocations and no application startup allocations; the focused test, three stack modes and the next full run pass. GraalVM 17 `InstrumentTests.instrumentAll` reported `JVMTI_ERROR_FAILS_VERIFICATION`; clean-environment focused cases and the next full run pass. Both original causes remain unidentified.

The private snapshot/attach regression is built with `cmake --build build/core/native --target attachSnapshotTest` and run from the repository root:

```powershell
.\build\core\native\attach-snapshot.exe H:/GitRepos/async-profiler-windows/build/asyncProfiler.dll F:/jdks/graalvm-jdk-17.0.17+8.1 H:/GitRepos/async-profiler-windows/tests/upstream/build/test/classes
```

It requires the profiler's matching PDB beside the DLL and the compiled upstream `test/nonjava/JavaClass` fixture. It is excluded from distribution binaries and from the 80 upstream native unit cases.

## Known failures

- **JIT cost split** (`RecoveryTests.numbers` on GraalVM 25/21/17/EE 11 and Azul 11 C2): the `Numbers.main;loop;avg` ratio can fall to 0.41–0.47 against the required 0.5 while `main;loop` passes. Graal inlines `avg` into `loop` and its PcDesc for a hot PC after the volatile store to `x` has scope `loop@4`, correctly attributing those samples to `Numbers.loop`. Azul 11 C2 can produce the same effect: its captured OSR nmethod's hot volatile-store/poll sequence PCs map to `loop@7`; its average-loop PCs retain `avg@27 → loop@1`. A targeted Azul profile reproduced the low ratio with complete stacks, and decoded scopes match the actual C2 metadata. Other C2 compilations keep a larger fraction in `avg`, so the numerical threshold varies with generated code.
- **libgraal compiler threads** (RecoveryTests.intrinsics on GraalVM EE 8/11, sporadic): 1.06-1.08% short stacks against a 1% limit. They are samples in `jvmcicompiler.dll`, whose PE unwind table covers only its C runtime, not the native-image Java code; later GraalVM releases emit that table.
- **Short or truncated CPU profiles** (intermittent, once each): ApiTests.flat on GraalVM 17 (elevated) dumped an empty profile; JfrTests.cpuLoad on Temurin 8 (not elevated) recorded no sample in the last 0.6 s of a 4 s recording, although its load thread was still running.
- **Live objects after a late collection** (JfrTests.allModeEventOverride, intermittent upstream timing, once on Temurin 25): the workload's sampled allocations are garbage, so `profiler.LiveObject` events cover only objects sampled since the last young collection; JDK 11+ recordings held 8 to 1,024 of them, and none when a collection fell at the end of the allocation loop.
- **Stalled agent start on GraalVM EE 8** (CpuTests.perfEventsRecordCpuEventsCount and perfEventsTargetCpuEventsCount, once each in one elevated run): the target did not complete the first `asprof` call's agent load within the 10 s profile timeout, and the JDK attach client waited in `connectPipe` until the process was ended; not reproduced in 12 further pinned captures.
- **ETW Java unwind metadata** (KernelTests.fdtransfer, once on GraalVM 17): the capture failed before sampling with "No Java unwind storage (metadata) ... carrier ... is outside the 4 GiB window, no granule within it is free and the granule below is occupied"; WhiteBox storage serves only code-cache records.
