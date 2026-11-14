/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
import java.lang.instrument.Instrumentation;
import java.lang.invoke.MethodHandles;
import one.profiler.AsyncProfiler;

public final class LegacyAnonymousInstrumentation {
    private static Instrumentation instrumentation;
    private static volatile Object sink;

    public static void premain(String options, Instrumentation value) {
        instrumentation = value;
    }

    private static Object ordinaryAnonymous() { return new Object() {}; }

    public static void main(String[] args) throws Throwable {
        if (!System.getProperty("java.specification.version").equals("1.8")) throw new AssertionError("This regression requires Java 8");
        MethodHandles.constant(Object.class, new Object()).invokeWithArguments();
        Class<?> anonymous = null;
        for (Class<?> type : instrumentation.getAllLoadedClasses()) {
            if (type.getName().startsWith("java.lang.invoke.LambdaForm$BMH/") && instrumentation.isModifiableClass(type)) {
                anonymous = type;
                break;
            }
        }
        if (anonymous == null) throw new AssertionError("No VM anonymous class with the JVM 8 modifiability bug");
        AsyncProfiler profiler = AsyncProfiler.getInstance(args[0]);
        String name = anonymous.getName();
        for (String target : new String[] {"event=" + name + ".<init>", "trace=" + name + ".reinvoke"}) {
            try {
                profiler.execute("start," + target);
                throw new AssertionError("VM anonymous target was accepted: " + target);
            } catch (IllegalStateException expected) {
                if (!expected.getMessage().contains("VM anonymous classes cannot be retransformed")) throw expected;
            }
        }
        String ordinary = ordinaryAnonymous().getClass().getName();
        if (ordinary.indexOf('/') >= 0) throw new AssertionError("Ordinary anonymous class has VM identity spelling");
        profiler.execute("start,event=" + ordinary + ".<init>");
        try {
            for (int i = 0; i < 3; ++i) sink = ordinaryAnonymous();
        } finally { profiler.stop(); }
        String folded = profiler.execute("collapsed");
        long samples = 0;
        for (String line : folded.split("\n")) {
            if (!line.trim().isEmpty()) samples += Long.parseLong(line.substring(line.lastIndexOf(' ') + 1));
        }
        if (samples != 3 || !folded.contains("LegacyAnonymousInstrumentation$1.<init>")) {
            throw new AssertionError("Ordinary anonymous constructors were lost: " + folded);
        }
        System.out.println("LEGACY_ANONYMOUS_INSTRUMENTATION_OK rejected=2 ordinaryConstructors=" + samples);
    }
}
