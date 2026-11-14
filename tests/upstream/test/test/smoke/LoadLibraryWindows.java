/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Derived from upstream test/test/smoke/LoadLibrary.java; modified for Windows x86-64.
 */

package test.smoke;

import test.stackwalker.StackGenerator;

// Windows variant of LoadLibrary. management.dll's JNI getters tail-jump into jvm.dll and leave no frame,
// so the library loaded late is the test library behind StackGenerator, whose JNI function keeps its frame.
public class LoadLibraryWindows {

    public static void main(String[] args) throws Exception {
        for (int i = 0; i < 20; i++) {
            Thread.sleep(100);
        }

        // Late load of jninativestacks.dll
        while (true) {
            StackGenerator.leafFrame();
        }
    }
}
