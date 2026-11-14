/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

package one.profiler.test;

import java.io.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

public class TestProcess implements Closeable {
    private static final Logger log = Logger.getLogger(TestProcess.class.getName());

    public static final String STDOUT = "%out";
    public static final String STDERR = "%err";
    public static final String PROFOUT = "%pout";
    public static final String PROFERR = "%perr";
    public static final String LIBPROF = "%lib";
    public static final String TESTBIN = "%testbin";
    public static final String TESTLIB = "%testlib";

    private static final String JAVA_HOME = System.getProperty("java.home");

    // The port's build output, relative to tests/upstream (the runner's working directory)
    private static final String WINDOWS_BUILD = "../../build";

    private static final Pattern filePattern = Pattern.compile("(%[a-z][a-z0-9_]*)(\\.[a-z]+)?");
    private static final Pattern shPreloadPattern = Pattern.compile("LD_PRELOAD=(\"[^\"]*\"|\\S+) ((?:\\w+=\\S* )*)");

    private static final MethodHandle pid = getPidHandle();

    private static MethodHandle getPidHandle() {
        // JDK 9+
        try {
            return MethodHandles.publicLookup().findVirtual(Process.class, "pid", MethodType.methodType(long.class));
        } catch (ReflectiveOperationException e) {
            // fallback
        }

        // JDK 8 on Windows: ProcessImpl keeps only the process handle
        if (System.getProperty("os.name").startsWith("Windows")) {
            try {
                Field f = Class.forName("java.lang.ProcessImpl").getDeclaredField("handle");
                f.setAccessible(true);
                System.load(new File("build/test/lib/processid.dll").getAbsolutePath());
                MethodHandle processId = MethodHandles.lookup().findStatic(TestProcess.class, "processId",
                        MethodType.methodType(long.class, long.class));
                return MethodHandles.filterReturnValue(MethodHandles.lookup().unreflectGetter(f), processId)
                        .asType(MethodType.methodType(long.class, Process.class));
            } catch (ReflectiveOperationException e) {
                throw new IllegalStateException("Unsupported API", e);
            }
        }

        // JDK 8
        try {
            Field f = Class.forName("java.lang.UNIXProcess").getDeclaredField("pid");
            f.setAccessible(true);
            return MethodHandles.lookup().unreflectGetter(f).asType(MethodType.methodType(long.class, Process.class));
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Unsupported API", e);
        }
    }

    // GetProcessId, from build/test/lib/processid.dll
    private static native long processId(long handle);

    private final Test test;
    private final Os currentOs;
    private final Jvm currentJvm;
    private final String logDir;
    private final String[] inputs;
    private final Process p;
    private final Map<String, File> tmpFiles = new HashMap<>();
    private final int timeout = 30;

    public TestProcess(Test test, Os currentOs, Jvm currentJvm, String logDir) throws Exception {
        this.test = test;
        this.currentOs = currentOs;
        this.currentJvm = currentJvm;
        this.logDir = logDir;
        this.inputs = test.inputs();

        List<String> cmd = buildCommandLine(test);
        log.log(Level.FINE, "Running " + String.join(" ", cmd));

        ProcessBuilder pb = new ProcessBuilder(cmd).inheritIO();
        if (test.output()) {
            pb.redirectOutput(createTempFile(STDOUT));
        }
        if (test.error()) {
            pb.redirectError(createTempFile(STDERR));
        }

        for (String env : test.env()) {
            String[] keyValue = env.split("=", 2);
            if (keyValue.length == 2 && !(currentOs == Os.WINDOWS && keyValue[0].equals("LD_PRELOAD"))) {
                pb.environment().put(keyValue[0], substituteFiles(keyValue[1]));
            }
        }
        pb.environment().put("TEST_JAVA_HOME", JAVA_HOME);

        this.p = pb.start();

        if (cmd.get(0).endsWith("java")) {
            // Give the JVM some time to initialize
            Thread.sleep(700);
        }
    }

    public Test test() {
        return this.test;
    }

    public String[] inputs() {
        return this.inputs;
    }

    public Os currentOs() {
        return this.currentOs;
    }

    public Jvm currentJvm() {
        return this.currentJvm;
    }

    public String profilerLibPath() {
        if (currentOs == Os.WINDOWS) {
            return WINDOWS_BUILD + "/asyncProfiler.dll";
        }
        return "build/lib/libasyncProfiler." + currentOs.getLibExt();
    }

    public String testBinPath() {
        return "build/test/bin";
    }

    public String testLibPath() {
        return "build/test/lib";
    }

    private List<String> buildCommandLine(Test test) {
        List<String> cmd = new ArrayList<>();

        String[] sh = test.sh();
        if (sh.length > 0) {
            // Windows uses Git for Windows sh from PATH
            cmd.add(currentOs == Os.WINDOWS ? "sh" : "/bin/sh");
            cmd.add("-e");
            cmd.add("-c");
            String script = substituteFiles(String.join(";", sh));
            cmd.add(currentOs == Os.WINDOWS ? windowsPreloads(script) : script);
        } else {
            if (currentOs == Os.WINDOWS) {
                for (String env : test.env()) {
                    if (env.startsWith("LD_PRELOAD=")) {
                        addPreloadLauncher(cmd, substituteFiles(env.substring("LD_PRELOAD=".length())));
                    }
                }
            }
            cmd.add(System.getProperty("java.home") + "/bin/java");
            cmd.add("-cp");
            cmd.add(System.getProperty("java.class.path"));
            if (test.debugNonSafepoints()) {
                cmd.add("-XX:+UnlockDiagnosticVMOptions");
                cmd.add("-XX:+DebugNonSafepoints");
            }
            // ETW unwind records for compiled code must lie within 32-bit RVAs of the code cache, where other
            // reservations, on GraalVM libgraal's compiler isolates, can leave no room. The documented launch-time
            // workaround is WhiteBox's VM-owned code buffer. GraalVM EE 8's WhiteBox has none, so it runs the Graal
            // compiler as jargraal, which reserves no isolates; elsewhere jargraal's startup compilation burst would
            // slow the first capture's stop past the profile timeout.
            if (currentOs == Os.WINDOWS && test.etw()) {
                cmd.add("-XX:+UnlockDiagnosticVMOptions");
                cmd.add("-XX:+WhiteBoxAPI");
                if (currentJvm == Jvm.HOTSPOT && System.getProperty("java.specification.version").startsWith("1.")) {
                    cmd.add("-XX:-UseJVMCINativeLibrary");
                }
            }
            cmd.add("-Done.profiler.libraryPath=" + System.getProperty("one.profiler.libraryPath", profilerLibPath()));
            cmd.add("-Djava.library.path=" + testLibPath());
            cmd.add("-ea");
            addArgs(cmd, test.jvmArgs());
            if (!test.agentArgs().isEmpty()) {
                cmd.add("-agentpath:" + profilerLibPath() + "=" +
                        substituteFiles(test.agentArgs()));
            }
            cmd.add(test.mainClass().getName());
            addArgs(cmd, test.args());
        }

        return cmd;
    }

    // Windows has no LD_PRELOAD: the port's launcher loads the listed DLLs into the child before its entry point.
    private void addPreloadLauncher(List<String> cmd, String libs) {
        cmd.add(WINDOWS_BUILD + "/asprof-helper.exe");
        for (String lib : libs.split(" ")) {
            cmd.add("--preload");
            cmd.add(lib);
        }
        cmd.add("--");
    }

    // Rewrites "LD_PRELOAD=LIBS [VAR=VALUE ...] command" into "[VAR=VALUE ...] launcher LIBS -- command".
    private String windowsPreloads(String script) {
        Matcher m = shPreloadPattern.matcher(script);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            List<String> launcher = new ArrayList<>();
            addPreloadLauncher(launcher, m.group(1).replace("\"", ""));
            m.appendReplacement(sb, Matcher.quoteReplacement(m.group(2) + String.join(" ", launcher) + " "));
        }
        return m.appendTail(sb).toString();
    }

    private String getExtFromFile(File file) {
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            byte[] header = new byte[16];
            int bytes = raf.read(header);
            String s = bytes > 0 ? new String(header, 0, bytes, StandardCharsets.ISO_8859_1) : "";
            if (s.startsWith("<!DOCTYPE html>")) {
                return ".html";
            } else if (s.startsWith("FLR\0")) {
                return ".jfr";
            }
            return "";
        } catch (IOException e) {
            return "";
        }
    }

    private void addArgs(List<String> cmd, String args) {
        if (args != null && !args.isEmpty()) {
            args = substituteFiles(args);
            for (StringTokenizer st = new StringTokenizer(args, " "); st.hasMoreTokens(); ) {
                cmd.add(st.nextToken());
            }
        }
    }

    private String substituteFiles(String s) {
        Matcher m = filePattern.matcher(s);
        if (!m.find()) {
            return s;
        }

        StringBuffer sb = new StringBuffer();
        do {
            String path = substituteFile(m.group(1), m.group(2));
            m.appendReplacement(sb, path);
        } while (m.find());

        return m.appendTail(sb).toString();
    }

    private String substituteFile(String fileId, String ext) {
        if (fileId.equals(LIBPROF)) {
            return profilerLibPath();
        }
        if (fileId.equals(TESTBIN)) {
            return testBinPath();
        }
        if (fileId.equals(TESTLIB)) {
            return testLibPath();
        }
        String path = createTempFile(fileId, ext).getPath();
        // Backslashes would be escapes in sh and in Matcher replacements
        return currentOs == Os.WINDOWS ? path.replace('\\', '/') : path;
    }

    private File createTempFile(String fileId) {
        return createTempFile(fileId, null);
    }

    private File createTempFile(String fileId, String ext) {
        return tmpFiles.computeIfAbsent(fileId, key -> {
            try {
                return File.createTempFile("ap-" + key.substring(1), ext);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });
    }

    private void clearTempFiles() {
        for (File file : tmpFiles.values()) {
            file.delete();
        }
    }

    private void moveLog(File file, String name, boolean autoExtension) throws IOException {
        if (file != null) {
            String targetName = autoExtension ? name + getExtFromFile(file) : name;
            Files.move(file.toPath(), Paths.get(logDir, targetName), StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private void moveLogs() {
        if (logDir == null) {
            return;
        }

        try {
            Files.createDirectories(Paths.get(logDir));

            moveLog(tmpFiles.get(STDOUT), "stdout", true);
            moveLog(tmpFiles.get(STDERR), "stderr", false);

            for (String key : tmpFiles.keySet()) {
                if (!key.equals(STDERR) && !key.equals(STDOUT)) {
                    moveLog(tmpFiles.get(key), key.substring(1), true);
                }
            }
        } catch (IOException e) {
            log.log(Level.WARNING, "Failed to move logs", e);
        }
    }

    private boolean isRoot() {
        if (currentOs == Os.WINDOWS) {
            return isElevated();
        }
        try (Stream<String> lines = Files.lines(Paths.get("/proc/self/status"))) {
            return lines.anyMatch(s -> s.startsWith("Uid:") && s.matches("Uid:\\s+0\\s+0.*"));
        } catch (IOException e) {
            return false;
        }
    }

    // High or System mandatory integrity level
    private static boolean isElevated() {
        try {
            Process whoami = new ProcessBuilder("whoami", "/groups").redirectErrorStream(true).start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(whoami.getInputStream()))) {
                return reader.lines().anyMatch(s -> s.contains("S-1-16-12288") || s.contains("S-1-16-16384"));
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // On Windows the program often runs in a child of the started process (the commands of sh, the preload
    // launcher's target), which survives when only the started process is terminated. The profiler's
    // asprof-helper.exe processes (ETW session watchers, broker) are left running: they outlive their target to end
    // its ETW session.
    private static void destroyDescendants(Process p) {
        if (!System.getProperty("os.name").startsWith("Windows")) {
            return;
        }
        if (PROCESS_HANDLE) {
            ProcessTree.destroyChildren(p);
        } else {
            try {
                destroyDescendants((long) pid.invokeExact(p));
            } catch (Throwable e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private static final boolean PROCESS_HANDLE = hasProcessHandle();

    private static boolean hasProcessHandle() {
        try {
            Class.forName("java.lang.ProcessHandle");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    // JDK 8: from build/test/lib/processid.dll
    private static native void destroyDescendants(long pid);

    private static final class ProcessTree {
        static void destroyChildren(Process p) {
            p.children().forEach(ProcessTree::destroy);
        }

        private static void destroy(ProcessHandle process) {
            if (!process.info().command().map(command -> command.endsWith("\\asprof-helper.exe")).orElse(false)) {
                process.children().forEach(ProcessTree::destroy);
                process.destroyForcibly();
            }
        }
    }

    @Override
    public void close() {
        destroyDescendants(p);
        p.destroy();

        try {
            waitForExit(p, 20);
        } catch (TimeoutException e) {
            log.log(Level.WARNING, "Failed to terminate child process", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            moveLogs();
            clearTempFiles();
        }
    }

    public long pid() {
        try {
            return (long) pid.invokeExact(p);
        } catch (Throwable e) {
            throw new IllegalStateException("Unsupported API", e);
        }
    }

    public int exitCode() {
        return p.exitValue();
    }

    public void waitForExit() throws TimeoutException, InterruptedException {
        waitForExit(p, timeout);
    }

    public Output waitForExit(String fileId) throws TimeoutException, InterruptedException {
        waitForExit(p, timeout);
        return readFile(fileId);
    }

    private void waitForExit(Process p, int seconds) throws TimeoutException, InterruptedException {
        if (!p.waitFor(seconds, TimeUnit.SECONDS)) {
            destroyDescendants(p);
            p.destroyForcibly();
            throw new TimeoutException("Child process has not exited");
        }
    }

    public Output profile(String args) throws IOException, TimeoutException, InterruptedException {
        return profile(args, false, 10);
    }

    public Output profile(String args, boolean sudo) throws IOException, TimeoutException, InterruptedException {
        return profile(args, sudo, 10);
    }

    public Output profile(String args, boolean sudo, int timeout) throws IOException, TimeoutException, InterruptedException {
        List<String> cmd = new ArrayList<>();
        if (currentOs == Os.WINDOWS) {
            // Upstream CI runs these cases as root; on Windows the runner itself must be elevated.
            if (sudo && !isRoot()) {
                throw new IllegalStateException("Elevated profiling needs an elevated test runner");
            }
            cmd.add(new File(WINDOWS_BUILD, "asprof.exe").getCanonicalPath());
        } else {
            if (sudo && (new File("/usr/bin/sudo").exists() || !isRoot())) {
                cmd.add("/usr/bin/sudo");
            }
            cmd.add("build/bin/asprof");
        }
        addArgs(cmd, args);
        cmd.add(Long.toString(pid()));
        log.log(Level.FINE, "Profiling " + cmd);

        Process p = new ProcessBuilder(cmd)
                .redirectOutput(createTempFile(PROFOUT))
                .redirectError(createTempFile(PROFERR))
                .start();

        waitForExit(p, timeout);
        int exitCode = p.waitFor();
        if (exitCode != 0) {
            throw new IOException("Profiling call failed: " + readFile(PROFERR));
        }

        return readFile(PROFOUT);
    }

    public void awaitFile(String fileId) throws IOException, TimeoutException, InterruptedException {
        Path path = getFile(fileId).toPath();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeout);
        try (WatchService watch = FileSystems.getDefault().newWatchService()) {
            path.getParent().register(watch, StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_CREATE);
            while (Files.size(path) == 0) {
                if (!p.isAlive()) {
                    throw new IOException("Child process exited with code " + p.exitValue() + " before writing " + fileId);
                }
                long remaining = deadline - System.nanoTime();
                WatchKey key = remaining > 0 ? watch.poll(remaining, TimeUnit.NANOSECONDS) : null;
                if (key == null) {
                    if (!p.isAlive()) {
                        throw new IOException("Child process exited with code " + p.exitValue() + " before writing " + fileId);
                    }
                    throw new TimeoutException("Child process has not written " + fileId);
                }
                key.pollEvents();
                if (!key.reset()) {
                    throw new IOException("Readiness watch directory is unavailable: " + path.getParent());
                }
            }
        }
    }

    public File getFile(String fileId) {
        return tmpFiles.get(fileId);
    }

    public String getFilePath(String fileId) {
        return getFile(fileId).getAbsolutePath();
    }

    public Output readFile(String fileId) {
        File f = getFile(fileId);
        try (Stream<String> stream = Files.lines(f.toPath())) {
            return new Output(stream.toArray(String[]::new));
        } catch (IOException | UncheckedIOException e) {
            return new Output(new String[0]);
        }
    }
}
