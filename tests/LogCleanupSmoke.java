/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import one.profiler.AsyncProfiler;

public final class LogCleanupSmoke {
    private static native String capi(byte[] command);

    @FunctionalInterface
    interface Command { void execute(String command) throws Exception; }

    static void temporary(Path directory, String name, Command command, boolean runtimeError) throws Exception {
        var log = directory.resolve("asprof-log." + name + ".txt");
        Exception failure = null;
        try {
            command.execute((runtimeError ? "stop" : "version") + ",log=" + log);
        } catch (Exception error) {
            failure = error;
        }
        // No profiling command may run between this call and deletion: opening
        // another log would hide the original handle-lifetime defect.
        Files.delete(log);
        if (runtimeError) {
            if (!(failure instanceof IllegalStateException) || !failure.getMessage().contains("not active")) {
                throw new AssertionError("Expected native runtime error for " + name, failure);
            }
        } else if (failure != null) throw failure;
        System.out.println("TEMPORARY_LOG_CLEANUP_OK " + name);
    }

    public static void main(String[] args) throws Exception {
        var profiler = AsyncProfiler.getInstance(Path.of(args[0]).toAbsolutePath().toString());
        System.load(Path.of(args[1]).toAbsolutePath().toString());
        var directory = Path.of(args[2]);
        var binary = AsyncProfiler.class.getDeclaredMethod("execute1", String.class);
        binary.setAccessible(true);
        Command c = command -> {
            var error = capi(command.getBytes(StandardCharsets.UTF_8));
            if (error != null) throw new IllegalStateException(error);
        };
        Command string = command -> {
            if (profiler.execute(command).isBlank()) throw new AssertionError("JNI string command returned no output");
        };
        Command bytes = command -> {
            try {
                var output = (byte[]) binary.invoke(profiler, command);
                if (output.length == 0) throw new AssertionError("JNI binary command returned no output");
            } catch (InvocationTargetException error) {
                if (error.getCause() instanceof Exception cause) throw cause;
                throw error;
            }
        };
        var commands = List.of(c, string, bytes);
        var names = List.of("capi", "jni-string", "jni-binary");
        for (var i = 0; i < commands.size(); i++) {
            temporary(directory, names.get(i) + "-success", commands.get(i), false);
            temporary(directory, names.get(i) + "-runtime-error", commands.get(i), true);
        }
        var persistent = directory.resolve("ordinary-profiler.log");
        c.execute("version,log=" + persistent);
        try {
            Files.delete(persistent);
            throw new AssertionError("An ordinary named log was closed after its command");
        } catch (IOException expected) {
            if (!Files.isRegularFile(persistent)) throw expected;
        }
        c.execute("version");
        Files.delete(persistent);
        System.out.println("ORDINARY_LOG_LIFETIME_OK");
    }
}
