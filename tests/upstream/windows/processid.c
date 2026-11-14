/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * Process helpers for the runner on JDK 8, which lacks Process.pid() and ProcessHandle.
 */

#include <jni.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <wchar.h>

JNIEXPORT jlong JNICALL Java_one_profiler_test_TestProcess_processId(JNIEnv* env, jclass cls, jlong handle) {
    return GetProcessId((HANDLE)(intptr_t)handle);
}

static ULONGLONG creationTime(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    FILETIME creation, exit, kernel, user;
    ULONGLONG result = 0;
    if (process) {
        if (GetProcessTimes(process, &creation, &exit, &kernel, &user)) {
            result = (ULONGLONG)creation.dwHighDateTime << 32 | creation.dwLowDateTime;
        }
        CloseHandle(process);
    }
    return result;
}

// A parent ID may name a reused PID; a child is never created before its parent.
static void destroyChildren(const PROCESSENTRY32W* entries, int count, DWORD parent) {
    ULONGLONG parentCreation = creationTime(parent);
    if (!parentCreation) return;
    for (int i = 0; i < count; i++) {
        if (entries[i].th32ParentProcessID != parent || entries[i].th32ProcessID == parent) continue;
        if (_wcsicmp(entries[i].szExeFile, L"asprof-helper.exe") == 0) continue;
        if (creationTime(entries[i].th32ProcessID) < parentCreation) continue;
        destroyChildren(entries, count, entries[i].th32ProcessID);
        HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, entries[i].th32ProcessID);
        if (process) {
            TerminateProcess(process, 1);
            CloseHandle(process);
        }
    }
}

JNIEXPORT void JNICALL Java_one_profiler_test_TestProcess_destroyDescendants(JNIEnv* env, jclass cls, jlong pid) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    int count = 0, capacity = 1024;
    PROCESSENTRY32W* entries = malloc(capacity * sizeof(PROCESSENTRY32W));
    PROCESSENTRY32W entry = {sizeof(PROCESSENTRY32W)};
    for (BOOL more = Process32FirstW(snapshot, &entry); more; more = Process32NextW(snapshot, &entry)) {
        if (count == capacity) entries = realloc(entries, (capacity *= 2) * sizeof(PROCESSENTRY32W));
        entries[count++] = entry;
    }
    CloseHandle(snapshot);
    destroyChildren(entries, count, (DWORD)pid);
    free(entries);
}
