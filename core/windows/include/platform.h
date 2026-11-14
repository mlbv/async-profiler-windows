/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <winsock2.h>
#include <windows.h>
#include <cstdint>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include "paths.h"

static_assert(sizeof(void*) == 8 && sizeof(long) == 4, "Windows x86-64 ABI required");
static_assert(sizeof(off_t) == 8, "Recording file offsets must be 64 bits");
#ifndef SIGPROF
#define SIGPROF 27
#define SIGVTALRM 26
#define SIGTRAP 5
#define SIGIO 29
#endif
struct siginfo_t {
    int si_signo;
    int si_code;
    int si_pid;
    int si_fd;
    int si_overrun;
    void* si_addr;
    union { int sival_int; void* sival_ptr; } si_value;
};
inline tm* localtime_r(const time_t* source, tm* target) { return localtime_s(target, source) == 0 ? target : nullptr; }
extern "C" ssize_t pwrite(int, const void*, size_t, off_t);
extern "C" int asprof_open(const char*, int, int);
extern "C" int pipe(int*);
extern "C" int fcntl(int, int, ...);
#define F_SETFL 4
#define O_NONBLOCK 0x4000
#ifndef MAX
#define MAX(left, right) ((left) > (right) ? (left) : (right))
#endif
#ifndef MIN
#define MIN(left, right) ((left) < (right) ? (left) : (right))
#endif
#include "windowsProfiler.h"
