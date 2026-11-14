/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "os.h"
#include "windowsProfiler.h"
#include "windowsSamplingTimer.h"
#include "windowsTscRate.h"
#include "log.h"
#include "sys/mman.h"
#include "sys/utsname.h"
#include <winternl.h>
#include <psapi.h>
#include <sddl.h>
#include <cstddef>
#include <tlhelp32.h>
#include <io.h>
#include <fcntl.h>
#include <cpuid.h>
#include <algorithm>
#include <vector>
#include <cstring>
#include <cerrno>
#include <atomic>

extern "C" ssize_t asprof_pread(int, void*, size_t, off_t);

namespace {
size_t systemPageSize() { SYSTEM_INFO info; GetSystemInfo(&info); return info.dwPageSize; }
std::uint64_t fileTime(const FILETIME& value) { return (std::uint64_t(value.dwHighDateTime) << 32) | value.dwLowDateTime; }
using QuerySystem = NTSTATUS (NTAPI*)(SYSTEM_INFORMATION_CLASS, void*, ULONG, ULONG*);
QuerySystem querySystem = reinterpret_cast<QuerySystem>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));

struct ThreadInfo { int tid; ThreadState state; std::uint64_t cpu; std::uint64_t creation; std::uint64_t userCpu; };
thread_local ThreadInfo selectedThread{};
struct ThreadCpuClock {
    WindowsProfiler::TscRate rate{};
    const char* error = WindowsProfiler::measureTscRate(rate);
};
const ThreadCpuClock& threadCpuClock() {
    static const ThreadCpuClock clock;
    return clock;
}
using NextProcessThread = NTSTATUS (NTAPI*)(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, HANDLE*);
using QueryThreadSnapshot = NTSTATUS (NTAPI*)(HANDLE, ULONG, void*, ULONG, ULONG*);
NextProcessThread nextProcessThread = reinterpret_cast<NextProcessThread>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtGetNextThread"));
QueryThreadSnapshot queryThreadSnapshot = reinterpret_cast<QueryThreadSnapshot>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
u32 samplingThreadFailure = 0;
// ThreadSystemThreadInformation is omitted from the public THREADINFOCLASS enum.
constexpr ULONG samplingThreadInformation = 40;
// ThreadLastSystemCall reports the system call and first argument of a thread blocked in one without waking it,
// and fails for a running thread. It requires THREAD_GET_CONTEXT.
constexpr ULONG lastSystemCallInformation = 21;
struct LastSystemCall { void* argument; USHORT number; USHORT reserved[3]; ULONG64 waitTime; };
static_assert(sizeof(SYSTEM_THREAD_INFORMATION) == 80);

struct ProcessHandle {
    HANDLE value = nullptr;
    ~ProcessHandle() { if (value) CloseHandle(value); }
};

bool systemProcesses(std::vector<unsigned char>& data) {
    if (data.empty()) data.resize(256 * 1024);
    for (;;) {
        ULONG required = 0;
        NTSTATUS result = querySystem(SystemProcessInformation, data.data(), static_cast<ULONG>(data.size()), &required);
        if (result == static_cast<NTSTATUS>(0xc0000004)) { data.resize(required + 65536); continue; }
        return result >= 0;
    }
}

class WindowsThreadList final : public ThreadList {
    std::vector<ThreadInfo> _threads;
    std::vector<unsigned char> _data;
    bool _process_only;

    void append(const SYSTEM_THREAD_INFORMATION& thread) {
        if (thread.ThreadState == 4) return;
        _threads.push_back({static_cast<int>(reinterpret_cast<std::uintptr_t>(thread.ClientId.UniqueThread)),
            thread.ThreadState == 5 || thread.ThreadState == 8 ? THREAD_SLEEPING : THREAD_RUNNING,
            static_cast<std::uint64_t>(thread.Reserved1[0].QuadPart + thread.Reserved1[1].QuadPart) * 100,
            static_cast<std::uint64_t>(thread.Reserved1[2].QuadPart),
            static_cast<std::uint64_t>(thread.Reserved1[1].QuadPart) * 100});
    }

    void updateProcessThreads() {
        ProcessHandle thread;
        for (;;) {
            HANDLE next = nullptr;
            NTSTATUS status = nextProcessThread(GetCurrentProcess(), thread.value, THREAD_QUERY_INFORMATION, 0, 0, &next);
            if (thread.value) CloseHandle(thread.value);
            thread.value = status >= 0 ? next : nullptr;
            if (status == static_cast<NTSTATUS>(0x8000001a)) return;
            if (status >= 0) {
                SYSTEM_THREAD_INFORMATION info{};
                status = queryThreadSnapshot(thread.value, samplingThreadInformation, &info, sizeof(info), nullptr);
                if (status >= 0) { append(info); continue; }
            }
            storeRelease(samplingThreadFailure, static_cast<u32>(status));
            _threads.clear();
            return;
        }
    }

public:
    explicit WindowsThreadList(bool process_only = false) : _process_only(process_only) { update(); }
    int next() override { selectedThread = _threads[_index++]; return selectedThread.tid; }
    void update() override {
        _threads.clear(); _index = 0; _count = 0;
        if (_process_only) {
            updateProcessThreads();
            _count = static_cast<u32>(_threads.size());
            return;
        }
        if (!systemProcesses(_data)) return;
        auto process = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(_data.data());
        for (;;) {
            if (reinterpret_cast<std::uintptr_t>(process->UniqueProcessId) == GetCurrentProcessId()) {
                auto threads = reinterpret_cast<SYSTEM_THREAD_INFORMATION*>(process + 1);
                for (ULONG i = 0; i < process->NumberOfThreads; ++i) {
                    append(threads[i]);
                }
                break;
            }
            if (!process->NextEntryOffset) break;
            process = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<unsigned char*>(process) + process->NextEntryOffset);
        }
        _count = static_cast<u32>(_threads.size());
    }
};

struct ProcessSnapshot {
    SYSTEM_PROCESS_INFORMATION info;
    char state;
};
thread_local std::vector<unsigned char> processData;
thread_local std::vector<ProcessSnapshot> processCache;

bool takeProcessSnapshot() {
    processCache.clear();
    if (!systemProcesses(processData)) return false;
    auto process = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(processData.data());
    for (;;) {
        if (process->UniqueProcessId != NULL) {
            char state = 'S';
            auto threads = reinterpret_cast<SYSTEM_THREAD_INFORMATION*>(process + 1);
            for (ULONG i = 0; i < process->NumberOfThreads; ++i) {
                ULONG value = threads[i].ThreadState;
                if (value == 1 || value == 2 || value == 3 || value == 6) { state = 'R'; break; }
            }
            processCache.push_back({*process, state});
        }
        if (!process->NextEntryOffset) break;
        process = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<unsigned char*>(process) + process->NextEntryOffset);
    }
    std::sort(processCache.begin(), processCache.end(), [](const ProcessSnapshot& a, const ProcessSnapshot& b) {
        return reinterpret_cast<std::uintptr_t>(a.info.UniqueProcessId) < reinterpret_cast<std::uintptr_t>(b.info.UniqueProcessId);
    });
    return true;
}

const ProcessSnapshot* findProcess(int pid) {
    auto found = std::lower_bound(processCache.begin(), processCache.end(), static_cast<DWORD>(pid),
            [](const ProcessSnapshot& entry, DWORD wanted) {
                return reinterpret_cast<std::uintptr_t>(entry.info.UniqueProcessId) < wanted;
            });
    return found != processCache.end() && reinterpret_cast<std::uintptr_t>(found->info.UniqueProcessId) == static_cast<DWORD>(pid)
            ? &*found : NULL;
}

// Per-process queries read the calling thread's snapshot from getProcessIds; a pid it lacks takes a new one.
const ProcessSnapshot* cachedProcess(int pid) {
    if (auto entry = findProcess(pid)) return entry;
    return takeProcessSnapshot() ? findProcess(pid) : NULL;
}

template<size_t N> bool copyUtf8(char (&target)[N], std::string_view text) {
    size_t count = std::min(N - 1, text.size());
    if (count < text.size()) while (count && (static_cast<unsigned char>(text[count]) & 0xc0) == 0x80) --count;
    memcpy(target, text.data(), count);
    target[count] = 0;
    return count != text.size();
}

using QueryProcess = NTSTATUS (NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
QueryProcess queryProcess = reinterpret_cast<QueryProcess>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));

template<class Pointer> struct RemoteUnicodeString {
    USHORT length, capacity;
    Pointer buffer;
};
template<class Pointer> struct RemoteParameters {
    BYTE reserved1[16];
    Pointer reserved2[10];
    RemoteUnicodeString<Pointer> imageName;
    RemoteUnicodeString<Pointer> commandLine;
};
template<class Pointer> struct RemotePEB {
    BYTE reserved[4];
    Pointer reserved3[2];
    Pointer loader;
    Pointer parameters;
};
static_assert(offsetof(RemotePEB<std::uint64_t>, parameters) == offsetof(PEB, ProcessParameters));
static_assert(offsetof(RemoteParameters<std::uint64_t>, commandLine) == offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine));

template<class T> bool readRemote(HANDLE process, std::uintptr_t address, T& value) {
    SIZE_T copied;
    return ReadProcessMemory(process, reinterpret_cast<void*>(address), &value, sizeof(value), &copied) && copied == sizeof(value);
}

template<class Pointer> bool readCommandLine(HANDLE process, std::uintptr_t pebAddress, ProcessInfo* info) {
    Pointer parameters;
    if (!readRemote(process, pebAddress + offsetof(RemotePEB<Pointer>, parameters), parameters)) return false;
    RemoteUnicodeString<Pointer> command;
    if (!readRemote(process, parameters + offsetof(RemoteParameters<Pointer>, commandLine), command)
            || command.length % sizeof(wchar_t) || command.length > command.capacity) return false;
    std::wstring text(command.length / sizeof(wchar_t), L'\0');
    SIZE_T copied;
    if (command.length && (!ReadProcessMemory(process, reinterpret_cast<void*>(static_cast<std::uintptr_t>(command.buffer)),
            text.data(), command.length, &copied) || copied != command.length)) return false;
    auto encoded = WindowsProfiler::utf8(text);
    if (!text.empty() && encoded.empty()) return false;
    if (copyUtf8(info->cmdline, encoded)) info->windows_available |= PROCESS_COMMAND_LINE_TRUNCATED;
    return true;
}

void processCommandLine(HANDLE process, ProcessInfo* info) {
    if (info->pid == OS::processId()) {
        auto command = WindowsProfiler::utf8(GetCommandLineW());
        if (copyUtf8(info->cmdline, command)) info->windows_available |= PROCESS_COMMAND_LINE_TRUNCATED;
        info->windows_available |= PROCESS_COMMAND_LINE;
        return;
    }
    ULONG_PTR wow64 = 0;
    if (queryProcess(process, ProcessWow64Information, &wow64, sizeof(wow64), NULL) < 0) return;
    if (wow64) {
        if (readCommandLine<std::uint32_t>(process, wow64, info)) info->windows_available |= PROCESS_COMMAND_LINE;
    } else {
        PROCESS_BASIC_INFORMATION basic;
        if (queryProcess(process, ProcessBasicInformation, &basic, sizeof(basic), NULL) >= 0
                && readCommandLine<std::uint64_t>(process, reinterpret_cast<std::uintptr_t>(basic.PebBaseAddress), info)) {
            info->windows_available |= PROCESS_COMMAND_LINE;
        }
    }
}

void processUser(HANDLE process, ProcessInfo* info) {
    HANDLE token;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) return;
    ProcessHandle retained{token};
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    if (!size) return;
    std::vector<unsigned char> data(size);
    if (!GetTokenInformation(token, TokenUser, data.data(), size, &size)) return;
    LPWSTR sid;
    if (ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid, &sid)) {
        copyUtf8(info->user_sid, WindowsProfiler::utf8(sid));
        LocalFree(sid);
        info->windows_available |= PROCESS_USER_SID;
    }
}

// The extended structure is available in newer Windows SDKs; preserve its ABI
// when building with a MinGW SDK that defines only PROCESS_MEMORY_COUNTERS_EX.
struct ProcessMemoryCountersV2 {
    PROCESS_MEMORY_COUNTERS_EX base;
    SIZE_T privateWorkingSet;
    ULONG64 sharedCommit;
};
void processMemory(HANDLE process, ProcessInfo* info) {
    ProcessMemoryCountersV2 counters{};
    if (!GetProcessMemoryInfo(process, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters), sizeof(counters))) {
        counters = {};
        if (!GetProcessMemoryInfo(process, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters.base), sizeof(counters.base))) return;
    }
    if (counters.base.cb >= sizeof(counters.base)) {
        info->private_commit = counters.base.PrivateUsage;
        info->windows_available |= PROCESS_PRIVATE_COMMIT;
    }
    if (counters.base.cb >= sizeof(counters)) {
        info->private_working_set = counters.privateWorkingSet;
        info->shared_commit = counters.sharedCommit;
        info->windows_available |= PROCESS_PRIVATE_WORKING_SET | PROCESS_SHARED_COMMIT;
    }
}

std::atomic<SigAction> signalActions[WindowsProfiler::MAX_PROFILING_SIGNAL + 1]{};
SigAction crashAction;
}

const size_t OS::page_size = systemPageSize();
const size_t OS::page_mask = OS::page_size - 1;
const long OS::clock_ticks_per_sec = 10000000;

u64 OS::nanotime() {
    static const u64 frequency = [] { LARGE_INTEGER value; QueryPerformanceFrequency(&value); return value.QuadPart; }();
    LARGE_INTEGER value; QueryPerformanceCounter(&value);
    return static_cast<u64>((static_cast<unsigned __int128>(value.QuadPart) * 1000000000) / frequency);
}
u64 OS::micros() {
    FILETIME time; GetSystemTimePreciseAsFileTime(&time);
    return (fileTime(time) - 116444736000000000ULL) / 10;
}
u64 OS::processStartTime() {
    FILETIME start, end, kernel, user;
    return GetProcessTimes(GetCurrentProcess(), &start, &end, &kernel, &user) ? (fileTime(start) - 116444736000000000ULL) / 10000 : 0;
}
void OS::sleep(u64 nanos) { Sleep(static_cast<DWORD>((nanos + 999999) / 1000000)); }
void OS::uninterruptibleSleep(u64 nanos, volatile bool* flag) {
    u64 end = nanotime() + nanos;
    while (*flag) {
        u64 now = nanotime();
        if (now >= end) break;
        sleep(std::min<u64>(end - now, 10000000));
    }
}

Error WindowsProfiler::prepareThreadCpuClock() {
    return Error(threadCpuClock().error);
}

Error WindowsProfiler::prepareSamplingThreads() {
    storeRelease(samplingThreadFailure, 0);
    if (!nextProcessThread || !queryThreadSnapshot) return Error("Windows process-scoped thread snapshots are unavailable");
    SYSTEM_THREAD_INFORMATION info{};
    NTSTATUS status = queryThreadSnapshot(GetCurrentThread(), samplingThreadInformation, &info, sizeof(info), nullptr);
    if (status >= 0) {
        ProcessHandle thread;
        status = nextProcessThread(GetCurrentProcess(), nullptr, THREAD_QUERY_INFORMATION, 0, 0, &thread.value);
    }
    if (status < 0) {
        storeRelease(samplingThreadFailure, static_cast<u32>(status));
        Log::error("Windows thread snapshot capability failed: NTSTATUS 0x%08x", static_cast<u32>(status));
        return Error("Windows process-scoped thread information is unavailable");
    }
    return Error::OK;
}

ThreadList* WindowsProfiler::listSamplingThreads() { return new WindowsThreadList(true); }
u32 WindowsProfiler::samplingThreadError() { return loadAcquire(samplingThreadFailure); }

Error WindowsProfiler::SamplingTimer::open() {
    storeRelease(_error, 0);
    _timer = CreateWaitableTimerExW(nullptr, nullptr, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_MODIFY_STATE | SYNCHRONIZE);
    if (_timer == nullptr) {
        storeRelease(_error, GetLastError());
        Log::error("Windows sampling timer creation failed: %u", _error);
        return Error("Cannot create a high-resolution Windows sampling timer");
    }
    _cancel = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (_cancel == nullptr) {
        storeRelease(_error, GetLastError());
        Log::error("Windows sampling cancellation event creation failed: %u", _error);
        close();
        return Error("Cannot create the Windows sampling cancellation event");
    }
    return Error::OK;
}

bool WindowsProfiler::SamplingTimer::wait(u64 nanos) {
    LARGE_INTEGER due;
    due.QuadPart = -static_cast<LONGLONG>((nanos + 99) / 100);
    if (!SetWaitableTimerEx(_timer, &due, 0, nullptr, nullptr, nullptr, 0)) {
        storeRelease(_error, GetLastError());
        return false;
    }
    HANDLE events[] = {_cancel, _timer};
    DWORD result = WaitForMultipleObjects(2, events, FALSE, INFINITE);
    if (result == WAIT_OBJECT_0 + 1) return true;
    if (result != WAIT_OBJECT_0) storeRelease(_error, result == WAIT_FAILED ? GetLastError() : ERROR_GEN_FAILURE);
    return false;
}

bool WindowsProfiler::SamplingTimer::waitUntil(u64 deadline) {
    u64 now = OS::nanotime();
    return wait(deadline > now ? deadline - now : 1);
}

u64 WindowsProfiler::SamplingTimer::measurePeriod() {
    // The first wait aligns to a tick; each following minimal wait lasts one period.
    u64 periods[9];
    if (!wait(1)) return 0;
    for (auto& period : periods) {
        u64 start = OS::nanotime();
        if (!wait(1)) return 0;
        period = OS::nanotime() - start;
    }
    std::nth_element(periods, periods + 4, periods + 9);
    return periods[4];
}

void WindowsProfiler::SamplingTimer::cancel() { SetEvent(_cancel); }

void WindowsProfiler::SamplingTimer::close() {
    if (_timer != nullptr) { CancelWaitableTimer(_timer); CloseHandle(_timer); _timer = nullptr; }
    if (_cancel != nullptr) { CloseHandle(_cancel); _cancel = nullptr; }
}
u64 OS::overrun(siginfo_t* info) { return info ? info->si_overrun : 0; }
u64 OS::hton64(u64 value) { return __builtin_bswap64(value); }
u64 OS::ntoh64(u64 value) { return __builtin_bswap64(value); }
int OS::getMaxThreadId() { return 0x1000000; }
int OS::processId() { return static_cast<int>(GetCurrentProcessId()); }
int OS::threadId() { int tid = WindowsProfiler::sampledThreadId(); return tid ? tid : static_cast<int>(GetCurrentThreadId()); }
const char* OS::schedPolicy(int tid) {
    if (tid == 0) tid = threadId();
    HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (!thread) return NULL;
    int priority = GetThreadPriority(thread); CloseHandle(thread);
    return priority == THREAD_PRIORITY_TIME_CRITICAL ? "TIME_CRITICAL" : priority == THREAD_PRIORITY_IDLE ? "IDLE" : "NORMAL";
}
bool OS::threadName(int tid, char* buffer, size_t size) {
    HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (!thread) return false;
    PWSTR name = NULL;
    HRESULT result = GetThreadDescription(thread, &name);
    CloseHandle(thread);
    if (FAILED(result)) return false;
    auto text = WindowsProfiler::utf8(name); LocalFree(name);
    if (text.empty()) return false;
    size_t length = std::min(size - 1, text.size());
    memcpy(buffer, text.data(), length); buffer[length] = 0;
    return true;
}
ThreadState OS::threadState(int tid) {
    if (tid == 0) tid = threadId();
    if (tid == WindowsProfiler::sampledThreadId()) return static_cast<ThreadState>(WindowsProfiler::sampledThreadState());
    if (tid == selectedThread.tid) return selectedThread.state;
    WindowsThreadList list;
    while (list.hasNext()) { if (list.next() == tid) return selectedThread.state; }
    return THREAD_UNKNOWN;
}
std::uint64_t WindowsProfiler::threadFingerprint(HANDLE thread) {
    LastSystemCall call;
    if (queryThreadSnapshot(thread, lastSystemCallInformation, &call, sizeof(call), nullptr) < 0) return 0;
    return ((std::uint64_t(call.number) << 48) ^ reinterpret_cast<std::uintptr_t>(call.argument)) | std::uint64_t(1) << 63;
}
u64 OS::threadFingerprint(int tid) {
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT, FALSE, tid);
    if (!thread) return 0;
    u64 fingerprint = WindowsProfiler::threadFingerprint(thread);
    CloseHandle(thread);
    return fingerprint;
}
u64 OS::threadCpuTime(int tid) {
    if (tid == 0) tid = threadId();
    HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (!thread) return 0;
    ULONG64 cycles;
    bool success = QueryThreadCycleTime(thread, &cycles);
    CloseHandle(thread);
    return success ? threadCpuClock().rate.nanos(cycles) : 0;
}
ThreadList* OS::listThreads() { return new WindowsThreadList; }
bool OS::isLinux() { return false; }
bool OS::isMusl() { return false; }
SigAction OS::installSignalHandler(int signal, SigAction action, SigHandler) {
    if (!WindowsProfiler::validProfilingSignal(signal)) { errno = EINVAL; return NULL; }
    return signalActions[signal].exchange(action, std::memory_order_acq_rel);
}
SigAction OS::replaceCrashHandler(SigAction action) { SigAction previous = crashAction; crashAction = action; return previous; }
int OS::getProfilingSignal(int mode) { return mode == 0 ? SIGPROF : SIGVTALRM; }
bool OS::sendSignalToThread(int tid, int signal) {
    return WindowsProfiler::validProfilingSignal(signal) && WindowsProfiler::sampleThread(tid, signal);
}

namespace WindowsProfiler {
bool readThreadCounter(int tid, bool cycles, std::uint64_t& value, std::uint64_t& creation, bool userOnly) {
    if (cycles && userOnly) return false;
    if (!cycles && tid == selectedThread.tid) {
        value = userOnly ? selectedThread.userCpu : selectedThread.cpu;
        creation = selectedThread.creation;
        return true;
    }
    HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(tid));
    if (!thread) return false;
    FILETIME start, end, kernel, user;
    ULONG64 count = 0;
    bool success = GetThreadTimes(thread, &start, &end, &kernel, &user) != FALSE;
    if (cycles) success &= QueryThreadCycleTime(thread, &count) != FALSE;
    CloseHandle(thread);
    if (!success) return false;
    creation = fileTime(start);
    value = cycles ? count : (fileTime(user) + (userOnly ? 0 : fileTime(kernel))) * 100;
    return true;
}
void deliverSample(int signal, siginfo_t* info, CONTEXT* context) {
    if (validProfilingSignal(signal)) {
        if (auto action = signalActions[signal].load(std::memory_order_acquire)) action(signal, info, context);
    }
}
}

void* OS::safeAlloc(size_t size) { return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); }
void OS::safeFree(void* address, size_t) { VirtualFree(address, 0, MEM_RELEASE); }
bool OS::getCpuDescription(char* buffer, size_t size) {
    unsigned int words[12];
    for (unsigned i = 0; i < 3; ++i) __cpuid(0x80000002 + i, words[i * 4], words[i * 4 + 1], words[i * 4 + 2], words[i * 4 + 3]);
    size_t length = std::min(size - 1, sizeof(words)); memcpy(buffer, words, length); buffer[length] = 0; return true;
}
int OS::getCpuCount() { return GetActiveProcessorCount(ALL_PROCESSOR_GROUPS); }
u64 OS::getProcessCpuTime(u64* user, u64* kernel) {
    FILETIME start, end, kt, ut;
    if (!GetProcessTimes(GetCurrentProcess(), &start, &end, &kt, &ut)) return 0;
    *user = fileTime(ut); *kernel = fileTime(kt); return *user + *kernel;
}
u64 OS::getTotalCpuTime(u64* user, u64* kernel) {
    FILETIME idle, kt, ut;
    if (!GetSystemTimes(&idle, &kt, &ut)) return 0;
    *user = fileTime(ut); *kernel = fileTime(kt) - fileTime(idle); return fileTime(ut) + fileTime(kt);
}
int OS::createMemoryFile(const char*) {
    wchar_t directory[MAX_PATH], filename[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, directory) || !GetTempFileNameW(directory, L"apr", 0, filename)) return -1;
    HANDLE file = CreateFileW(filename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (file == INVALID_HANDLE_VALUE) { DeleteFileW(filename); return -1; }
    return _open_osfhandle(reinterpret_cast<intptr_t>(file), _O_BINARY | _O_RDWR);
}
bool OS::copyFile(int source, int destination, off_t offset, size_t size) {
    unsigned char buffer[65536];
    while (size) {
        ssize_t count = asprof_pread(source, buffer, std::min(size, sizeof(buffer)), offset);
        if (count <= 0) return false;
        ssize_t written = 0;
        while (written < count) {
            int next = _write(destination, buffer + written, static_cast<unsigned>(count - written));
            if (next <= 0) return false;
            written += next;
        }
        offset += count; size -= count;
    }
    return true;
}
void OS::freePageCache(int, off_t) {}
int OS::mprotect(void* address, size_t size, int prot) {
    DWORD protection = prot & PROT_EXEC ? (prot & PROT_WRITE ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ)
            : prot & PROT_WRITE ? PAGE_READWRITE : prot & PROT_READ ? PAGE_READONLY : PAGE_NOACCESS;
    DWORD previous;
    if (VirtualProtect(address, size, protection, &previous)) { FlushInstructionCache(GetCurrentProcess(), address, size); return 0; }
    WindowsProfiler::ioError(GetLastError()); return -1;
}
extern "C" int mprotect(void* address, size_t size, int prot) { return OS::mprotect(address, size, prot); }
u64 OS::getSystemBootTime() { return (micros() / 1000 - GetTickCount64()) / 1000; }
u64 OS::getRamSize() { MEMORYSTATUSEX memory{sizeof(memory)}; return GlobalMemoryStatusEx(&memory) ? memory.ullTotalPhys : 0; }
int OS::getProcessIds(int* pids, int maximum) {
    if (!takeProcessSnapshot()) return 0;
    int count = std::min<int>(maximum, processCache.size());
    for (int i = 0; i < count; ++i) pids[i] = static_cast<int>(reinterpret_cast<std::uintptr_t>(processCache[i].info.UniqueProcessId));
    return count;
}

bool OS::getBasicProcessInfo(int pid, ProcessInfo* info) {
    auto entry = cachedProcess(pid);
    if (!entry) return false;
    const auto& source = entry->info;
    info->pid = pid;
    info->ppid = static_cast<int>(reinterpret_cast<std::uintptr_t>(source.InheritedFromUniqueProcessId));
    info->state = entry->state;
    info->start_time = (source.CreateTime.QuadPart - 116444736000000000ULL) / 10000;
    info->cpu_user = source.UserTime.QuadPart / 10000000.0;
    info->cpu_system = source.KernelTime.QuadPart / 10000000.0;
    info->threads = source.NumberOfThreads;
    info->vm_size = source.VirtualMemoryCounters.VirtualSize;
    info->vm_rss = source.VirtualMemoryCounters.WorkingSetSize;
    info->page_faults = source.VirtualMemoryCounters.PageFaultCount;
    info->io_read = source.IoCounters.ReadTransferCount;
    info->io_write = source.IoCounters.WriteTransferCount;
    auto name = WindowsProfiler::utf8(std::wstring_view(source.ImageName.Buffer, source.ImageName.Length / sizeof(wchar_t)));
    if (copyUtf8(info->name, name)) info->windows_available |= PROCESS_NAME_TRUNCATED;
    return true;
}

bool OS::getDetailedProcessInfo(ProcessInfo* info) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, info->pid);
    if (!process) process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, info->pid);
    if (!process) return true; // Snapshot metrics remain valid; optional fields are explicitly unavailable.
    ProcessHandle retained{process};
    FILETIME start, end, kernel, user;
    auto entry = cachedProcess(info->pid);
    if (!GetProcessTimes(process, &start, &end, &kernel, &user) || !entry
            || fileTime(start) != static_cast<std::uint64_t>(entry->info.CreateTime.QuadPart)) return false;
    processCommandLine(process, info);
    processUser(process, info);
    processMemory(process, info);
    return true;
}

JitWriteProtection::JitWriteProtection(bool) : _prev(0), _restore(false) {}
JitWriteProtection::~JitWriteProtection() {}

extern "C" int uname(utsname* info) {
    OSVERSIONINFOW version{sizeof(version)};
    using GetVersion = LONG (WINAPI*)(OSVERSIONINFOW*);
    auto getVersion = reinterpret_cast<GetVersion>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
    if (getVersion(&version) < 0) return -1;
    strcpy(info->sysname, "Windows"); strcpy(info->machine, "x86_64");
    snprintf(info->release, sizeof(info->release), "%lu.%lu.%lu", version.dwMajorVersion, version.dwMinorVersion, version.dwBuildNumber);
    strncpy(info->version, info->release, sizeof(info->version));
    wchar_t computer[256]; DWORD length = 256;
    if (!GetComputerNameW(computer, &length)) return -1;
    auto name = WindowsProfiler::utf8(std::wstring_view(computer, length));
    strncpy(info->nodename, name.c_str(), sizeof(info->nodename) - 1); info->nodename[sizeof(info->nodename) - 1] = 0;
    return 0;
}
