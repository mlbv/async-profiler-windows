/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
// Elevated ground truth for the ETW stack-part rules used by software events. Probe
// threads run distinct functions in timed phases and log each phase start; every user
// stack part assigned to a sample, by its own key or shared within a kernel-mode
// interval, must name the function the thread ran at that sample's time.
//   switches: the sample is a switch-out, keyed by the thread's next switch-in.
//   faults:   the sample is a page fault, keyed by its own time.
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <bcrypt.h>
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>
#include <thread>
#include <vector>

namespace {
constexpr GUID threadProvider = {0x3d6fa8d1, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
constexpr GUID faultProvider = {0x3d6fa8d3, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
constexpr GUID stackProvider = {0xdef2fe46, 0x7bd6, 0x4b80, {0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0x0d, 0x0c, 0xe3}};
constexpr int phases = 9, probes = 8;
constexpr std::uint64_t boundaryTicks = 2000;
template<class T> T read(const void* data, size_t offset) { T value; std::memcpy(&value, static_cast<const char*>(data) + offset, sizeof(value)); return value; }
std::uint64_t qpc() { LARGE_INTEGER value; QueryPerformanceCounter(&value); return value.QuadPart; }
bool faults = false;
std::atomic<bool> stopping{false};

template<int N> [[clang::optnone]] __declspec(noinline) void phase(std::uint64_t until) {
    if (faults) {
        // First writes to fresh pages fault in this function.
        auto pages = static_cast<volatile char*>(VirtualAlloc(nullptr, 8 << 20, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        for (size_t offset = 0; offset < (8u << 20) && qpc() < until; offset += 4096) pages[offset] = N;
        VirtualFree(const_cast<char*>(pages), 0, MEM_RELEASE);
        return;
    }
    volatile std::uint64_t value = N;
    while (qpc() < until) for (int i = 0; i < 20000; i++) value = value * (N + 3) + i;
}
[[clang::optnone]] __declspec(noinline) void waitPhase(std::uint64_t) {
    if (!faults) { Sleep(1); return; }
    // The file system writes into fresh pages: kernel-mode faults under this function.
    auto buffer = VirtualAlloc(nullptr, 1 << 20, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    auto file = CreateFileW(L"C:/Windows/System32/ntdll.dll", GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    DWORD read = 0;
    ReadFile(file, buffer, 1 << 20, &read, nullptr);
    CloseHandle(file);
    VirtualFree(buffer, 0, MEM_RELEASE);
}
using Phase = void (*)(std::uint64_t);
const Phase functions[phases] = {phase<0>, phase<1>, phase<2>, phase<3>, phase<4>, phase<5>, phase<6>, phase<7>, waitPhase};
std::uintptr_t begins[phases], ends[phases];

struct Start { std::uint64_t time; int function; };
std::mutex lock;
std::map<DWORD, std::vector<Start>*> threads;
struct Event { std::uint64_t time; int kind; DWORD tid; std::uint64_t key; std::vector<std::uint64_t> frames; };
std::vector<Event> events;  // kind 0: switch-out, 1: switch-in or fault, 2: stack part

void WINAPI onEvent(EVENT_RECORD* record) {
    const auto& header = record->EventHeader;
    auto opcode = header.EventDescriptor.Opcode;
    std::uint64_t time = header.TimeStamp.QuadPart;
    if (!faults && IsEqualGUID(header.ProviderId, threadProvider) && opcode == 36) {
        DWORD incoming = read<DWORD>(record->UserData, 0), outgoing = read<DWORD>(record->UserData, 4);
        if (threads.contains(outgoing)) events.push_back({time, 0, outgoing, time, {}});
        if (threads.contains(incoming)) events.push_back({time, 1, incoming, time, {}});
    } else if (faults && IsEqualGUID(header.ProviderId, faultProvider) && opcode >= 10 && opcode <= 15) {
        if (threads.contains(header.ThreadId)) events.push_back({time, 1, header.ThreadId, time, {}});
    } else if (IsEqualGUID(header.ProviderId, stackProvider) && opcode == 32) {
        DWORD tid = read<DWORD>(record->UserData, 12);
        if (!threads.contains(tid)) return;
        Event event{time, 2, tid, read<std::uint64_t>(record->UserData, 0), std::vector<std::uint64_t>((record->UserDataLength - 16) / 8)};
        for (size_t i = 0; i < event.frames.size(); ++i) event.frames[i] = read<std::uint64_t>(record->UserData, 16 + 8 * i);
        events.push_back(std::move(event));
    }
}
int functionOf(std::uint64_t pc) {
    for (int i = 0; i < phases; ++i) if (pc >= begins[i] && pc < ends[i]) return i;
    return -1;
}
// The function running at time, or -1 near a phase boundary.
int truth(const std::vector<Start>& starts, std::uint64_t time) {
    auto next = std::upper_bound(starts.begin(), starts.end(), time, [](std::uint64_t value, const Start& start) { return value < start.time; });
    if (next == starts.begin() || time - std::prev(next)->time < boundaryTicks || (next != starts.end() && next->time - time < boundaryTicks)) return -1;
    return std::prev(next)->function;
}
struct Properties { EVENT_TRACE_PROPERTIES base; wchar_t name[64]; };
}

int main(int argc, char** argv) {
    faults = argc == 2 && std::strcmp(argv[1], "faults") == 0;
    if (argc != 2 || (!faults && std::strcmp(argv[1], "switches") != 0)) { std::puts("etw-user-parts-test switches|faults (elevated)"); return 2; }
    for (int i = 0; i < phases; ++i) {
        DWORD64 image;
        auto entry = RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(functions[i]), &image, nullptr);
        if (!entry) { std::puts("Probe function has no unwind entry"); return 2; }
        begins[i] = image + entry->BeginAddress; ends[i] = image + entry->EndAddress;
    }
    Properties properties{};
    auto& session = properties.base;
    session.Wnode.BufferSize = sizeof(properties); session.Wnode.Flags = WNODE_FLAG_TRACED_GUID; session.Wnode.ClientContext = 1;
    BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&session.Wnode.Guid), sizeof(GUID), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    std::swprintf(properties.name, 64, L"etw-user-parts-%lu", GetCurrentProcessId());
    session.LoggerNameOffset = offsetof(Properties, name);
    session.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    session.BufferSize = 64; session.MinimumBuffers = 64; session.MaximumBuffers = 1024; session.FlushTimer = 1;
    TRACEHANDLE handle = 0;
    if (auto error = StartTraceW(&handle, properties.name, &session)) { std::printf("StartTrace failed: %lu\n", error); return 2; }
    std::vector<CLASSIC_EVENT_ID> stacked(faults ? 6 : 1);
    for (size_t i = 0; i < stacked.size(); ++i) {
        stacked[i].EventGuid = faults ? faultProvider : threadProvider;
        stacked[i].Type = static_cast<UCHAR>(faults ? 10 + i : 36);
    }
    TraceSetInformation(handle, TraceStackTracingInfo, stacked.data(), static_cast<ULONG>(stacked.size() * sizeof(CLASSIC_EVENT_ID)));
    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName = properties.name;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    logfile.EventRecordCallback = onEvent;
    auto consumer = OpenTraceW(&logfile);
    std::atomic<int> ready{0};
    std::atomic<bool> go{false};
    std::vector<std::thread> workers;
    for (int index = 0; index < probes; ++index) workers.emplace_back([&, index] {
        auto starts = new std::vector<Start>;
        { std::lock_guard guard(lock); threads[GetCurrentThreadId()] = starts; }
        ready++;
        while (!go) Sleep(1);
        for (int next = index; !stopping; ++next) {
            auto function = next % phases;
            auto start = qpc();
            starts->push_back({start, function});
            functions[function](start + 30000 + 997 * index);
        }
    });
    while (ready < probes) Sleep(1);
    // Oversubscription preempts the spinning probes in user mode.
    std::vector<std::thread> hogs;
    for (unsigned i = 0; !faults && i < std::thread::hardware_concurrency() + 8; ++i)
        hogs.emplace_back([] { volatile std::uint64_t value = 0; while (!stopping) value = value + 1; });
    std::thread processor([&] { ProcessTrace(&consumer, 1, nullptr, nullptr); });
    ULONG flags[8] = {static_cast<ULONG>(EVENT_TRACE_FLAG_THREAD | (faults ? EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS : EVENT_TRACE_FLAG_CSWITCH))};
    TraceSetInformation(handle, TraceSystemTraceEnableFlagsInfo, flags, sizeof(flags));
    go = true;
    Sleep(5000);
    stopping = true;
    for (auto& worker : workers) worker.join();
    for (auto& hog : hogs) hog.join();
    ControlTraceW(handle, nullptr, &session, EVENT_TRACE_CONTROL_STOP);
    processor.join();
    CloseTrace(consumer);

    // Replay with the engine's rule: a user part completes its own key and later keys of
    // the thread that already hold a kernel part; earlier waiting keys have none.
    struct Waiting { std::uint64_t sampleTime, key; bool kernel = false; };
    std::map<DWORD, std::uint64_t> switchedOut;
    std::map<DWORD, std::vector<Waiting>> waiting;
    std::uint64_t own = 0, shared = 0, mismatches = 0, boundary = 0, released = 0;
    for (const auto& event : events) {
        if (event.kind == 0) { switchedOut[event.tid] = event.time; continue; }
        if (event.kind == 1) {
            if (faults) waiting[event.tid].push_back({event.time, event.time});
            else if (auto out = switchedOut.find(event.tid); out != switchedOut.end()) {
                waiting[event.tid].push_back({out->second, event.time});
                switchedOut.erase(out);
            }
            continue;
        }
        auto& keys = waiting[event.tid];
        auto user = std::find_if(event.frames.begin(), event.frames.end(), [](std::uint64_t pc) { return !(pc >> 63); });
        if (user == event.frames.end()) {
            for (auto& key : keys) if (key.key == event.key) key.kernel = true;
            continue;
        }
        int named = -1;
        for (auto frame = user; frame != event.frames.end() && named < 0; ++frame) if (!(*frame >> 63)) named = functionOf(*frame);
        std::vector<Waiting> remaining;
        for (const auto& key : keys) {
            if (key.key < event.key) { released++; continue; }
            if (key.key > event.key && !key.kernel) { remaining.push_back(key); continue; }
            auto expected = truth(*threads[event.tid], key.sampleTime);
            if (expected < 0 || named < 0) { boundary++; continue; }
            if (expected != named) mismatches++;
            else if (key.key == event.key) own++;
            else shared++;
        }
        keys.swap(remaining);
    }
    std::printf("ETW_USER_PARTS mode=%s lost=%lu own=%llu shared=%llu mismatches=%llu boundary=%llu released=%llu\n",
        faults ? "faults" : "switches", session.EventsLost, own, shared, mismatches, boundary, released);
    return mismatches || !own || session.EventsLost ? 1 : 0;
}
