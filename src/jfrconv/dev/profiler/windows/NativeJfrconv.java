/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
package dev.profiler.windows;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import org.graalvm.nativeimage.RuntimeOptions;
import org.graalvm.nativeimage.c.function.CFunction;
import org.graalvm.word.Pointer;

/**
 * jfr-converter.exe, a native image of one.convert.Main with upstream launcher.sh's command line. The image
 * is built with -H:-ParseRuntimeOptions, so only leading launcher options configure the runtime, and
 * they apply in-process. Arguments come from the raw command line because the C runtime also expands
 * wildcards inside quotes; like java.exe, only unquoted wildcards expand. The converter runs on a
 * thread sized by -Xss because the main thread's stack is fixed at link time.
 */
public final class NativeJfrconv {
    private static final long DEFAULT_STACK_SIZE = 2L << 20; // launcher.sh's -Xss2M

    private NativeJfrconv() {}

    @CFunction(transition = CFunction.Transition.NO_TRANSITION)
    private static native Pointer GetCommandLineW();

    public static void main(String[] ignored) throws Throwable {
        String[] args = commandLine();
        if (args.length > 0 && (args[0].equals("-v") || args[0].equals("--version"))) {
            System.out.println("JFR converter " + build("version") + " built on " + build("date"));
            return;
        }
        long stackSize = DEFAULT_STACK_SIZE;
        int count = 0;
        for (; count < args.length; count++) {
            String arg = args[count];
            String option;
            if ((arg.startsWith("-D") || arg.startsWith("-X")) && arg.length() > 2 || arg.startsWith("-agent")) {
                option = arg;
            } else if (arg.startsWith("-J")) {
                option = arg.substring(2);
            } else {
                break;
            }
            try {
                if (option.startsWith("-Xss")) {
                    stackSize = (Long) descriptor("StackSize").convertValue(option.substring(4));
                } else {
                    apply(option);
                }
            } catch (IllegalArgumentException e) {
                System.err.println("Error: " + e.getMessage());
                System.exit(1);
            }
        }
        String[] conversion = Arrays.copyOfRange(args, count, args.length);
        Throwable[] failure = new Throwable[1];
        Thread converter = new Thread(null, () -> {
            try {
                one.convert.Main.main(conversion);
            } catch (Throwable e) {
                failure[0] = e;
            }
        }, "main", stackSize);
        converter.start();
        converter.join();
        if (failure[0] != null) throw failure[0];
    }

    private static String build(String key) throws IOException {
        Properties build = new Properties();
        try (InputStream input = NativeJfrconv.class.getResourceAsStream("version.properties")) {
            build.load(input);
        }
        return build.getProperty(key);
    }

    /** The arguments after the program name, split and wildcard-expanded as java.exe's launcher does. */
    private static String[] commandLine() {
        Pointer raw = GetCommandLineW();
        StringBuilder text = new StringBuilder();
        for (int i = 0; raw.readChar(i * 2) != 0; i++) text.append(raw.readChar(i * 2));
        String line = text.toString();
        // The program name: quotes delimit it, without escapes.
        int at = 0;
        boolean quoted = false;
        for (; at < line.length() && (quoted || (line.charAt(at) != ' ' && line.charAt(at) != '\t')); at++) {
            if (line.charAt(at) == '"') quoted = !quoted;
        }
        List<String> args = new ArrayList<>();
        while (true) {
            while (at < line.length() && (line.charAt(at) == ' ' || line.charAt(at) == '\t')) at++;
            if (at == line.length()) break;
            at = next(line, at, args);
        }
        return args.toArray(new String[0]);
    }

    /** One argument per the JDK launcher's next_arg (libjli/cmdtoargs.c); returns the following position. */
    private static int next(String line, int at, List<String> args) {
        StringBuilder arg = new StringBuilder();
        int quotes = 0, slashes = 0;
        char prev = 0;
        boolean wildcard = false;
        for (; at < line.length(); at++) {
            char ch = line.charAt(at);
            if (ch == '"') {
                if (prev == '\\') {
                    for (int i = 1; i < slashes; i += 2) arg.append('\\');
                    if (slashes % 2 == 1) arg.append(ch);
                    else quotes++;
                } else if (prev == '"' && quotes % 2 == 0) {
                    quotes++;
                    arg.append(ch); // every other consecutive quote
                } else if (quotes == 0) {
                    quotes++;
                } else {
                    quotes--;
                }
                slashes = 0;
            } else if (ch == '\\') {
                slashes++;
            } else if (ch == ' ' || ch == '\t') {
                if (prev == '\\') for (int i = 0; i < slashes; i++) arg.append('\\');
                slashes = 0;
                if (quotes % 2 == 0) break;
                arg.append(ch);
            } else {
                if (prev == '\\') for (int i = 0; i < slashes; i++) arg.append('\\');
                if ((ch == '*' || ch == '?') && quotes % 2 == 0) wildcard = true;
                arg.append(ch);
                slashes = 0;
            }
            prev = ch;
        }
        if (prev == '\\') for (int i = 0; i < slashes; i++) arg.append('\\');
        String value = arg.toString();
        if (wildcard) expand(value, args);
        else args.add(value);
        return at;
    }

    /** sun.launcher.LauncherHelper.expandArgs: matches in the named directory, or the argument unchanged. */
    private static void expand(String arg, List<String> args) {
        File file = new File(arg);
        File parent = file.getParentFile() == null ? new File(".") : file.getParentFile();
        int entries = 0;
        try (DirectoryStream<Path> matches = Files.newDirectoryStream(parent.toPath(), file.getName())) {
            for (Path match : matches) {
                args.add(match.normalize().toString());
                entries++;
            }
        } catch (Exception e) {
            entries = 0;
        }
        if (entries == 0) args.add(arg);
    }

    private static void apply(String option) {
        if (option.startsWith("-D")) {
            int split = option.indexOf('=');
            if (split < 0) System.setProperty(option.substring(2), "");
            else System.setProperty(option.substring(2, split), option.substring(split + 1));
        } else if (option.startsWith("-Xms")) {
            set("MinHeapSize", option.substring(4));
        } else if (option.startsWith("-Xmx")) {
            set("MaxHeapSize", option.substring(4));
        } else if (option.startsWith("-Xmn")) {
            set("MaxNewSize", option.substring(4));
        } else if (option.startsWith("-XX:+") || option.startsWith("-XX:-")) {
            set(option.substring(5), String.valueOf(option.charAt(4) == '+'));
        } else if (option.startsWith("-XX:") && option.indexOf('=') > 4) {
            int split = option.indexOf('=');
            set(option.substring(4, split), option.substring(split + 1));
        } else {
            throw new IllegalArgumentException("The option '" + option + "' is not supported by Native Image");
        }
    }

    private static void set(String name, String value) {
        RuntimeOptions.set(name, descriptor(name).convertValue(value));
    }

    private static RuntimeOptions.Descriptor descriptor(String name) {
        RuntimeOptions.Descriptor descriptor = RuntimeOptions.getDescriptor(name);
        if (descriptor == null) throw new IllegalArgumentException("Could not find option '" + name + "'");
        return descriptor;
    }
}
