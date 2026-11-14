/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.io.BufferedReader;
import java.io.InputStreamReader;
import one.profiler.Recording;
import one.profiler.Span;

public final class NativeSpanFixture {
    static int work(int value) { return value * 3; }

    static java.net.URLClassLoader isolatedLoader(String jar) throws Exception {
        return new java.net.URLClassLoader(new java.net.URL[]{java.nio.file.Path.of(jar).toUri().toURL()}, ClassLoader.getPlatformClassLoader()) {
            @Override
            protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                if (!name.startsWith("one.profiler.")) return super.loadClass(name, resolve);
                synchronized (getClassLoadingLock(name)) {
                    var type = findLoadedClass(name);
                    if (type == null) type = findClass(name);
                    if (resolve) resolveClass(type);
                    return type;
                }
            }
        };
    }

    public static void main(String[] args) throws Exception {
        if (Recording.state() != Recording.UNAVAILABLE || Span.start() != 0) throw new AssertionError("SDK should be unavailable before installation");
        var input = new BufferedReader(new InputStreamReader(System.in));
        Class<?> preloaded = null;
        System.out.println("READY " + ProcessHandle.current().pid());
        for (var command = input.readLine(); command != null && !command.equals("quit"); command = input.readLine()) {
            if (command.equals("state")) {
                if (preloaded != null && !preloaded.getMethod("state").invoke(null).equals(Recording.state())) throw new AssertionError("Preloaded SDK state diverged");
                System.out.println("STATE " + Recording.state() + " " + Span.start()); continue;
            }
            if (command.equals("preload")) {
                preloaded = Class.forName("one.profiler.Recording", true, isolatedLoader(args[0]));
                if (!preloaded.getMethod("state").invoke(null).equals(Recording.UNAVAILABLE)) throw new AssertionError("Preloaded SDK should be unavailable");
                System.out.println("PRELOADED");
                continue;
            }
            if (command.equals("loader")) {
                try (var loader = isolatedLoader(args[0])) {
                    var recording = Class.forName("one.profiler.Recording", true, loader);
                    if (!recording.getMethod("state").invoke(null).equals(Recording.RUNNING)) throw new AssertionError("Isolated SDK copy did not bind");
                    var span = Class.forName("one.profiler.Span", true, loader);
                    var start = span.getMethod("start").invoke(null);
                    span.getMethod("end", long.class, String.class).invoke(null, start, "isolated");
                }
                System.out.println("LOADER_OK");
                continue;
            }
            if (Recording.state() != Recording.RUNNING || Recording.clockFrequency() <= 0) throw new AssertionError("SDK was not bound on attach");
            if (preloaded != null && !preloaded.getMethod("state").invoke(null).equals(Recording.RUNNING)) throw new AssertionError("Preloaded SDK was not rebound on attach");
            Span.endIfProfiled(Span.start(), "unsampled");
            var sum = 0;
            for (var i = 0; i < 10; ++i) {
                var start = Span.start();
                sum += work(i);
                Thread.sleep(2);
                Span.endIfProfiled(start, "sampled." + i);
            }
            Span.end(Span.start(), "");
            Span.end(Span.start(), null);
            var start = Recording.timestamp();
            Span.emit(start, start + 1_000_000, "zero\0emoji\ud83d\ude42");
            Span.emit(start + 1, start, "invalid-duration");
            for (var i = 0; i < 64; ++i) Span.end(Span.start(), "large." + i + ":" + "x".repeat(4096));
            try { Span.end(Span.start(), "x".repeat(8192)); throw new AssertionError("Oversized tag accepted"); }
            catch (IllegalArgumentException expected) { }
            try { Span.end(Span.start(), "\ud800"); throw new AssertionError("Unpaired surrogate accepted"); }
            catch (IllegalArgumentException expected) { }
            System.out.println("SPANS " + sum);
        }
    }
}
