/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#ifndef _STACKWALKER_H
#define _STACKWALKER_H

#include "arguments.h"
#include "event.h"
#include "vmEntry.h"


class JavaFrameAnchor;

class StackWalker {
  public:
    static int walkFP(void* ucontext, const void** callchain, int max_depth);
    static int walkDwarf(void* ucontext, const void** callchain, int max_depth);
    static int walkVM(void* ucontext, ASGCT_CallFrame* frames, int max_depth, int lock_index,
                      StackWalkFeatures features, EventType event_type);

    static int retainJavaFrames(ASGCT_CallFrame* frames, int depth) {
        int javaDepth = 0;
        for (int i = 0; i < depth; ++i) {
            if (frames[i].bci >= 0 || frames[i].bci == BCI_ERROR) frames[javaDepth++] = frames[i];
        }
        return javaDepth;
    }

    static void checkFault();
};

#endif // _STACKWALKER_H
