/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
package dev.profiler.windows;

import java.io.File;
import java.lang.management.ManagementFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * jfrconv.cmd's entry point, equivalent to upstream's launcher.sh. Leading -D, -X,
 * -agent and -J options configure the converter's JVM; they are parsed here because
 * cmd splits unquoted arguments at '=', ',' and ';'. Java 8 compatible.
 */
public final class Jfrconv {
    private Jfrconv() {}

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && (args[0].equals("-v") || args[0].equals("--version"))) {
            System.out.println(Version.line("JFR converter"));
            return;
        }
        List<String> options = new ArrayList<>();
        int count = 0;
        for (; count < args.length; count++) {
            String arg = args[count];
            if (arg.startsWith("-D") || arg.startsWith("-X")) {
                if (arg.length() > 2) options.add(arg);
            } else if (arg.startsWith("-agent")) {
                options.add(arg);
            } else if (arg.startsWith("-J")) {
                options.add(arg.substring(2));
            } else {
                break;
            }
        }
        String[] conversion = Arrays.copyOfRange(args, count, args.length);
        if (count == 0) {
            one.convert.Main.main(conversion);
            return;
        }
        List<String> command = new ArrayList<>();
        command.add(new File(System.getProperty("java.home"), "bin/java").getPath());
        command.addAll(ManagementFactory.getRuntimeMXBean().getInputArguments());
        command.addAll(options);
        command.add("-cp");
        command.add(new File(Jfrconv.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getPath());
        command.add("one.convert.Main");
        command.addAll(Arrays.asList(conversion));
        System.exit(new ProcessBuilder(command).inheritIO().start().waitFor());
    }
}
