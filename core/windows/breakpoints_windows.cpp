/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "windowsBreakpoints.h"
#include "windowsMutex.h"
#include "windowsNativeErrorState.h"
#include "importHooks.h"
#include "log.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <mutex>
#include <new>
#include <vector>

namespace WindowsProfiler::Breakpoints {
namespace {
using namespace Imports;
constexpr unsigned ROLE_COUNT = NATIVE_PROBE + 1;
struct Target {
    std::atomic<bool> active{false};
    std::atomic<unsigned> readers{0};
    std::atomic<std::uint64_t> generation{0};
    DWORD64 address = 0;
    unsigned control = 0;
    Callback callback = nullptr;
    void* parameter = nullptr;
    HMODULE provider = nullptr;
};
std::array<Target, ROLE_COUNT> targets;
std::atomic<unsigned> targetCount{0};
std::atomic<ThreadObserver> threadObserver{nullptr};
std::atomic<bool> broken{false};
WindowsMutex registryMutex;

struct Point {
    unsigned role, slot, control;
    DWORD64 address, originalAddress, originalControl;
    std::atomic<std::uint64_t> generation{0};
    std::uint64_t periodCount = 0;
    Point* older = nullptr;
};
struct alignas(Point) PointPage { PointPage* next; };
PointPage* pages;
Point* availablePoints;

Point* allocatePoint() {
    if (!availablePoints) {
        constexpr size_t pageSize = 65536;
        auto page = static_cast<PointPage*>(VirtualAlloc(nullptr, pageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!page) return nullptr;
        page->next = pages;
        pages = page;
        auto data = reinterpret_cast<unsigned char*>(page) + sizeof(PointPage);
        for (size_t offset = 0; offset + sizeof(Point) <= pageSize - sizeof(PointPage); offset += sizeof(Point)) {
            auto point = new (data + offset) Point{};
            point->older = availablePoints;
            availablePoints = point;
        }
    }
    auto point = availablePoints;
    availablePoints = point->older;
    point->older = nullptr;
    point->generation.store(0, std::memory_order_relaxed);
    point->periodCount = 0;
    return point;
}
void recyclePoint(Point* point) {
    if (!point) return;
    point->older = availablePoints;
    availablePoints = point;
}
struct Thread {
    std::atomic<DWORD> tid{0};
    std::atomic<bool> handling{false};
    HANDLE handle = nullptr;
    std::uint64_t creation = 0;
    std::atomic<Point*> points{nullptr};
};
std::array<Thread, 65536> threads;

DWORD64& debug_address(CONTEXT& context, unsigned slot) {
    switch (slot) { case 0: return context.Dr0; case 1: return context.Dr1; case 2: return context.Dr2; default: return context.Dr3; }
}
DWORD64 controlMask(unsigned slot) { return (DWORD64{3} << (slot * 2)) | (DWORD64{15} << (16 + slot * 4)); }
DWORD64 enabledControl(const Point& point) {
    return (DWORD64{1} << (point.slot * 2)) | (DWORD64{point.control} << (16 + point.slot * 4));
}
bool owns(CONTEXT& context, const Point& point) {
    return debug_address(context, point.slot) == point.address
            && (context.Dr7 & controlMask(point.slot)) == enabledControl(point);
}
bool active(const Point& point) {
    const auto& target = targets[point.role];
    return target.active.load(std::memory_order_acquire)
            && target.generation.load(std::memory_order_acquire) == point.generation.load(std::memory_order_acquire);
}
void restore(CONTEXT& context, const Point& point) {
    debug_address(context, point.slot) = point.originalAddress;
    context.Dr7 = (context.Dr7 & ~controlMask(point.slot)) | point.originalControl;
    context.Dr6 &= ~(DWORD64{1} << point.slot);
}
void reconcile(CONTEXT& context, Thread& thread, bool applyActive) {
    std::array<Point*, 4> desired{};
    for (auto point = thread.points.load(std::memory_order_acquire); point; point = point->older) {
        if (active(*point)) desired[point->slot] = point;
    }
    for (auto point = thread.points.load(std::memory_order_acquire); point; point = point->older) {
        if (!desired[point->slot] && owns(context, *point)) restore(context, *point);
    }
    if (applyActive) for (auto point : desired) if (point && active(*point)) {
        debug_address(context, point->slot) = point->address;
        context.Dr7 = (context.Dr7 & ~controlMask(point->slot)) | enabledControl(*point);
        context.Dr6 &= ~(DWORD64{1} << point->slot);
    }
}
void clearPoints(Thread& thread) {
    for (auto point = thread.points.exchange(nullptr); point;) { auto older = point->older; recyclePoint(point); point = older; }
}
constexpr DWORD tombstone = 0xffffffff;
size_t reapCursor;
void reap(Thread& thread) {
    if (!thread.handle || WaitForSingleObject(thread.handle, 0) != WAIT_OBJECT_0) return;
    CloseHandle(thread.handle);
    thread.handle = nullptr;
    clearPoints(thread);
    thread.creation = 0;
    thread.handling.store(false, std::memory_order_relaxed);
    thread.tid.store(tombstone, std::memory_order_release);
}
Thread* findThread(DWORD tid, bool create) {
    auto first = (tid >> 2) % threads.size();
    Thread* available = nullptr;
    for (size_t i = 0; i < threads.size(); ++i) {
        auto& entry = threads[(first + i) % threads.size()];
        auto key = entry.tid.load(std::memory_order_acquire);
        if (key == tid) return &entry;
        if (create && !available && (!key || key == tombstone || (entry.handle && WaitForSingleObject(entry.handle, 0) == WAIT_OBJECT_0))) available = &entry;
        if (!key) break;
    }
    if (available) {
        if (available->handle) CloseHandle(available->handle);
        available->handle = nullptr;
        clearPoints(*available);
        available->handling.store(false, std::memory_order_relaxed);
        available->tid.store(tid, std::memory_order_release);
    }
    return available;
}
std::uint64_t creationTime(HANDLE thread) {
    FILETIME creation, exit, kernel, user;
    if (!GetThreadTimes(thread, &creation, &exit, &kernel, &user)) return 0;
    return (std::uint64_t(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
}

struct DebugUpdate {
    HANDLE thread;
    bool suspended;
    bool (*update)(CONTEXT&, void*);
    void* argument;
    bool success = false;
};

DWORD WINAPI update_debug_registers(void* argument) {
    auto& request = *static_cast<DebugUpdate*>(argument);
    if (!request.suspended && SuspendThread(request.thread) == DWORD(-1)) {
        request.success = WaitForSingleObject(request.thread, 0) == WAIT_OBJECT_0;
        return 0;
    }
    CONTEXT context{};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    request.success = GetThreadContext(request.thread, &context) && request.update(context, request.argument)
            && SetThreadContext(request.thread, &context);
    if (!request.suspended && ResumeThread(request.thread) == DWORD(-1)) request.success = false;
    return 0;
}

bool update_debug_registers(HANDLE thread, DWORD tid, bool suspended, bool (*update)(CONTEXT&, void*), void* argument) {
    DebugUpdate request{thread, suspended, update, argument};
    if (tid != GetCurrentThreadId()) update_debug_registers(&request);
    else {
        // CONTEXT_DEBUG_REGISTERS cannot be read/set reliably on oneself.
        // The helper uses only Win32 context calls while this caller is stopped.
        auto helper = CreateThread(nullptr, 0, update_debug_registers, &request, 0, nullptr);
        if (!helper) return false;
        WaitForSingleObject(helper, INFINITE);
        CloseHandle(helper);
    }
    return request.success;
}


LONG CALLBACK onException(EXCEPTION_POINTERS* exception) {
    if (exception->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
    // Access the x64 TEB directly because a thread API may itself be profiled.
    DWORD tid;
    __asm__("movl %%gs:0x48, %0" : "=r"(tid));
    auto thread = findThread(tid, false);
    if (!thread) return EXCEPTION_CONTINUE_SEARCH;
    auto& context = *exception->ContextRecord;
    auto point = thread->points.load(std::memory_order_acquire);
    for (; point; point = point->older) {
        if ((context.Dr6 & (DWORD64{1} << point->slot)) && owns(context, *point)
                && (point->control != 0 || context.Rip == point->address)) break;
    }
    if (!point) return EXCEPTION_CONTINUE_SEARCH;
    DWORD savedError;
    __asm__ volatile("movl %%gs:0x68, %0" : "=r"(savedError));
    auto slot = point->slot;
    auto address = point->address;
    if (!thread->handling.exchange(true, std::memory_order_acq_rel)) {
        // Open/close a window before recording its boundary function; allocation
        // callbacks run last because they simulate a return from the VM hook.
        for (unsigned role : {2u, 3u, NATIVE_PROBE, 0u, 1u}) {
            auto& target = targets[role];
            target.readers.fetch_add(1, std::memory_order_acquire);
            for (auto current = thread->points.load(std::memory_order_acquire); current; current = current->older) {
                if (current->role == role && current->slot == slot && current->address == address && active(*current)) {
                    target.callback(context, target.parameter);
                    break;
                }
            }
            target.readers.fetch_sub(1, std::memory_order_release);
        }
        thread->handling.store(false, std::memory_order_release);
    }
    if (point->control == 0) context.EFlags |= 0x10000; // Execution breakpoints precede the instruction.
    context.Dr6 &= ~(DWORD64{1} << point->slot);
    reconcile(context, *thread, true);
    __asm__ volatile("movl %0, %%gs:0x68" :: "r"(savedError) : "memory");
    return EXCEPTION_CONTINUE_EXECUTION;
}

bool installThread(HANDLE handle, DWORD tid, bool alreadySuspended) {
    std::lock_guard lock(registryMutex);
    if (!targetCount.load(std::memory_order_acquire)) return true;
    for (unsigned i = 0; i < 16; ++i) reap(threads[reapCursor++ % threads.size()]);
    auto thread = findThread(tid, true);
    if (!thread) return false;
    auto creation = creationTime(handle);
    if (!creation) return false;
    if (thread->creation != creation) {
        if (thread->handle) CloseHandle(thread->handle);
        thread->handle = nullptr;
        clearPoints(*thread);
        thread->handling.store(false, std::memory_order_relaxed);
        thread->creation = creation;
    }
    if (!thread->handle && !DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(), &thread->handle,
            0, FALSE, DUPLICATE_SAME_ACCESS)) return false;
    // No allocation or CRT work is allowed while the target is suspended.
    struct Install { Thread* thread; std::array<Point*, ROLE_COUNT> prepared{}; } request{thread};
    for (unsigned role = 0; role < ROLE_COUNT; ++role) if (targets[role].active.load(std::memory_order_acquire)) {
        request.prepared[role] = allocatePoint();
        if (!request.prepared[role]) {
            for (auto point : request.prepared) recyclePoint(point);
            return false;
        }
    }
    bool success = update_debug_registers(handle, tid, alreadySuspended, [](CONTEXT& context, void* data) {
        auto& request = *static_cast<Install*>(data);
        auto& thread = *request.thread;
        reconcile(context, thread, false);
        for (auto point = thread.points.load(std::memory_order_acquire); point; point = point->older) {
            if (active(*point) && !owns(context, *point)) return false;
        }
        for (unsigned role = 0; role < ROLE_COUNT; ++role) {
            auto& target = targets[role];
            if (!target.active.load(std::memory_order_acquire)) continue;
            bool installed = false;
            for (auto point = thread.points.load(std::memory_order_acquire); point; point = point->older) {
                if (point->role == role && active(*point)) { installed = true; break; }
            }
            if (installed) continue;
            unsigned slot = 0;
            Point* shared = nullptr;
            for (auto point = thread.points.load(std::memory_order_acquire); point; point = point->older) {
                if (active(*point) && point->address == target.address && point->control == target.control && owns(context, *point)) { shared = point; break; }
            }
            if (shared) slot = shared->slot;
            else {
                for (unsigned index = 0; index < 4; ++index) {
                    if ((context.Dr7 & (DWORD64{3} << (index * 2))) && debug_address(context, index) == target.address) {
                        bool ours = false;
                        for (auto point = thread.points.load(std::memory_order_acquire); point; point = point->older) {
                            ours |= point->slot == index && active(*point) && owns(context, *point);
                        }
                        if (!ours) return false;
                    }
                }
                while (slot < 4 && (context.Dr7 & (DWORD64{3} << (slot * 2)))) ++slot;
            }
            if (slot == 4) return false;
            auto mask = controlMask(slot);
            auto originalAddress = shared ? shared->originalAddress : debug_address(context, slot);
            auto originalControl = shared ? shared->originalControl : context.Dr7 & mask;
            Point* point = nullptr;
            for (auto old = thread.points.load(std::memory_order_acquire); old; old = old->older) {
                if (old->role == role && old->slot == slot && old->address == target.address && old->control == target.control
                        && old->originalAddress == originalAddress && old->originalControl == originalControl) { point = old; break; }
            }
            if (!point) {
                point = request.prepared[role];
                request.prepared[role] = nullptr;
                point->role = role; point->slot = slot; point->address = target.address;
                point->control = target.control;
                point->originalAddress = originalAddress; point->originalControl = originalControl;
                point->older = thread.points.load(std::memory_order_acquire);
                point->generation.store(target.generation.load(std::memory_order_acquire), std::memory_order_release);
                thread.points.store(point, std::memory_order_release);
            } else {
                // Rebinding an inactive Point represents a newly opened per-TID
                // event, even when the address and debug-register slot match.
                point->periodCount = 0;
                point->generation.store(target.generation.load(std::memory_order_acquire), std::memory_order_release);
            }
            debug_address(context, slot) = point->address;
            context.Dr7 = (context.Dr7 & ~mask) | enabledControl(*point);
            context.Dr6 &= ~(DWORD64{1} << slot);
        }
        return true;
    }, &request);
    for (auto point : request.prepared) recyclePoint(point);
    return success;
}

struct ThreadPolicy {
    static HANDLE invoke(decltype(&CreateThread) original, LPSECURITY_ATTRIBUTES security, SIZE_T stack,
            LPTHREAD_START_ROUTINE start, void* parameter, DWORD flags, LPDWORD tid) {
        auto observer = threadObserver.load(std::memory_order_acquire);
        if (!targetCount.load(std::memory_order_acquire) && !observer)
            return original(security, stack, start, parameter, flags, tid);
        DWORD created;
        auto result = original(security, stack, start, parameter, flags | CREATE_SUSPENDED, &created);
        auto prepare = [&] {
            if (result) {
                if (tid) *tid = created;
                if (targetCount.load(std::memory_order_acquire) && !installThread(result, created, true))
                    broken.store(true, std::memory_order_release);
                if (observer && !observer(result, created)) broken.store(true, std::memory_order_release);
                if (!(flags & CREATE_SUSPENDED) && ResumeThread(result) == DWORD(-1))
                    broken.store(true, std::memory_order_release);
            }
        };
        if (observer) {
            SavedNativeErrorState saved;
            prepare();
        } else {
            WindowsError saved;
            prepare();
        }
        return result;
    }
};
using ThreadHooks = FunctionHooks<ThreadPolicy, decltype(&CreateThread)>;

void validate(const void* address, HMODULE& provider, Access access, unsigned length) {
    MEMORY_BASIC_INFORMATION page;
    if (access != Access::Execute) {
        require(length == 1 || length == 2 || length == 4 || length == 8, "A data watchpoint length must be 1, 2, 4, or 8");
        require(reinterpret_cast<uintptr_t>(address) % length == 0, "A data watchpoint address must be aligned to its length");
        require(VirtualQuery(address, &page, sizeof(page)) != 0 && page.State == MEM_COMMIT
                && !(page.Protect & (PAGE_GUARD | PAGE_NOACCESS))
                && page.RegionSize >= length
                && reinterpret_cast<uintptr_t>(address) - reinterpret_cast<uintptr_t>(page.BaseAddress) <= page.RegionSize - length,
                "Data watchpoint memory is inaccessible");
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(address), &provider);
        require(provider != selfModule(), "Cannot watch profiler implementation data");
        return;
    }
    require(length == 1, "An execution breakpoint length must be 1");
    require(VirtualQuery(address, &page, sizeof(page)) != 0
            && (page.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)),
            "Breakpoint target is not executable");
    require(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            reinterpret_cast<LPCWSTR>(address), &provider) != 0, "Breakpoint target must belong to a loaded module");
    require(provider != selfModule(), "Cannot instrument profiler implementation code");
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    for (auto name : {"NtContinue", "ZwContinue", "RtlRestoreContext", "KiUserExceptionDispatcher", "RtlDispatchException", "RtlRaiseException", "RtlRaiseStatus"}) {
        auto entry = reinterpret_cast<DWORD64>(GetProcAddress(ntdll, name));
        if (!entry) continue;
        DWORD64 base;
        auto function = RtlLookupFunctionEntry(entry, &base, nullptr);
        auto target = reinterpret_cast<DWORD64>(address);
        require(target != entry && (!function || target < base + function->BeginAddress || target >= base + function->EndAddress),
                "Cannot instrument Windows exception-dispatch machinery");
    }
}
} // namespace

void initialize() {
    if (!AddVectoredExceptionHandler(1, onException)) {
        broken.store(true, std::memory_order_release);
        Log::error("Cannot install the Windows breakpoint exception handler");
    }
    Imports::import_rules.push_back({"CreateThread", Imports::windows_library, Imports::import_replacement<ThreadHooks>});
}
Error observeThreads(ThreadObserver observer) {
    static std::string message;
    if (!observer) return Error("Thread observer callback is required");
    if (auto error = prepareNativeErrorState()) return Error(error);
    bool published = false;
    try {
        Imports::initializeImportRules();
        ThreadObserver expected = nullptr;
        if (!threadObserver.compare_exchange_strong(expected, observer, std::memory_order_acq_rel))
            return Error("A native thread observer is already active");
        Imports::import_consumers.fetch_add(1, std::memory_order_release);
        published = true;
        Imports::refresh_imports();
        if (auto error = WindowsProfiler::importFailure()) {
            stopObservingThreads();
            return Error(error);
        }
        return Error::OK;
    } catch (const std::exception& error) {
        message = error.what();
        if (published) stopObservingThreads();
        return Error(message.c_str());
    }
}
void stopObservingThreads() {
    if (threadObserver.exchange(nullptr, std::memory_order_acq_rel))
        Imports::import_consumers.fetch_sub(1, std::memory_order_release);
}
bool failed() { return broken.load(std::memory_order_acquire); }
unsigned activeTargets() { return targetCount.load(std::memory_order_acquire); }
bool handling(DWORD tid) { auto thread = findThread(tid, false); return thread && thread->handling.load(std::memory_order_acquire); }

bool samplePeriod(unsigned role, std::uint64_t period) {
    DWORD tid;
    __asm__("movl %%gs:0x48, %0" : "=r"(tid));
    auto thread = findThread(tid, false);
    if (!thread) return false;
    for (auto point = thread->points.load(std::memory_order_acquire); point; point = point->older) {
        if (point->role == role && active(*point)) {
            if (++point->periodCount < period) return false;
            point->periodCount = 0;
            return true;
        }
    }
    return false;
}

void stop(unsigned role) {
    auto& target = targets[role];
    std::unique_lock lock(registryMutex);
    if (!target.active.exchange(false, std::memory_order_acq_rel)) return;
    targetCount.fetch_sub(1, std::memory_order_release);
    Imports::import_consumers.fetch_sub(1, std::memory_order_release);
    for (auto& thread : threads) {
        reap(thread);
        if (!thread.handle) continue;
        bool relevant = false;
        for (auto point = thread.points.load(std::memory_order_acquire); point; point = point->older) relevant |= point->role == role;
        if (!relevant) continue;
        if (!update_debug_registers(thread.handle, thread.tid.load(), false, [](CONTEXT& context, void* parameter) {
                reconcile(context, *static_cast<Thread*>(parameter), false);
                return true;
            }, &thread)) broken.store(true, std::memory_order_release);
    }
    lock.unlock();
    while (target.readers.load(std::memory_order_acquire)) SwitchToThread();
    if (target.provider) { FreeLibrary(target.provider); target.provider = nullptr; }
}

Error start(unsigned role, const void* address, Callback callback, void* parameter, Access access, unsigned length) {
    static std::string message;
    HMODULE provider = nullptr;
    bool published = false;
    try {
        require(role < ROLE_COUNT, "Invalid breakpoint role");
        require(!failed(), "A Windows breakpoint operation failed; restart the target");
        validate(address, provider, access, length);
        Imports::initializeImportRules();
        Imports::refresh_imports();
        {
            std::lock_guard lock(registryMutex);
            auto& target = targets[role];
            require(!target.active.load(), "Breakpoint role is already active");
            target.address = reinterpret_cast<DWORD64>(address);
            unsigned lengthBits = length == 8 ? 2 : length == 4 ? 3 : length == 2 ? 1 : 0;
            target.control = access == Access::Execute ? 0 : static_cast<unsigned>(access) | (lengthBits << 2);
            target.callback = callback;
            target.parameter = parameter;
            target.provider = provider; provider = nullptr;
            target.generation.fetch_add(1, std::memory_order_release);
            target.active.store(true, std::memory_order_release);
            targetCount.fetch_add(1, std::memory_order_release);
            Imports::import_consumers.fetch_add(1, std::memory_order_release);
            published = true;
        }
        HANDLE snapshot = WindowsProfiler::toolhelpSnapshot(TH32CS_SNAPTHREAD, 0);
        require(snapshot != INVALID_HANDLE_VALUE, "Cannot enumerate breakpoint threads");
        THREADENTRY32 entry{sizeof(entry)};
        bool success = Thread32First(snapshot, &entry) != 0;
        if (success) do {
            if (entry.th32OwnerProcessID != GetCurrentProcessId()) continue;
            auto handle = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT
                    | THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, entry.th32ThreadID);
            if (!handle) { success &= GetLastError() == ERROR_INVALID_PARAMETER; continue; }
            success &= installThread(handle, entry.th32ThreadID, false);
            CloseHandle(handle);
        } while (Thread32Next(snapshot, &entry));
        CloseHandle(snapshot);
        require(success, "Cannot install all Windows breakpoints; x64 has four hardware slots shared with debuggers");
        return Error::OK;
    } catch (const std::exception& error) {
        message = error.what();
        if (provider) FreeLibrary(provider);
        if (published) stop(role);
        return Error(message.c_str());
    }
}
} // namespace WindowsProfiler::Breakpoints
