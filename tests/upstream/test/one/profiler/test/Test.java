/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

package one.profiler.test;

import java.lang.annotation.ElementType;
import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Repeatable(Tests.class)
public @interface Test {

    String[] sh() default {};

    Class<?> mainClass() default Test.class;

    String args() default "";

    String agentArgs() default "";

    String jvmArgs() default "";

    String[] env() default {};

    boolean debugNonSafepoints() default false;

    // Windows: the profiler captures the test JVM's Java stacks through ETW.
    boolean etw() default false;

    boolean output() default false;

    boolean error() default false;

    Os[] os() default {};

    Arch[] arch() default {};

    Jvm[] jvm() default {};

    int[] jvmVer() default {};

    // Windows: modules whose matching PDBs the test needs, on the JVM versions in pdbJvmVer (all if empty).
    Pdb[] pdb() default {};

    int[] pdbJvmVer() default {};

    // Needs the JDK Flight Recorder (jdk.jfr) in the JVM under test.
    boolean jfr() default false;

    boolean enabled() default true;

    // Optional inputs to the test method.
    String[] inputs() default {};

    String nameSuffix() default "";

    boolean runIsolated() default false;
}
