/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsJavaUnwind.h"
#include "windowsJvmCodeStorage.h"
#include "windowsLeafUnwind.h"
#include "windowsCompiledUnwind.h"
#include "windowsCompiledHandlers.h"
#include "windowsInstructionDecoder.h"
#include "windowsMutex.h"
#include "vmStructs.h"
#include "vmEntry.h"
#include "stackFrame.h"
#include "writer.h"
#include "arguments.h"
#include "importHooks.h"
#include "profiler.h"
#include <algorithm>
#include <atomic>
#include <cstring>
#include <initializer_list>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

void VMStructs::snapshotInterpreterCodelets(std::vector<InterpreterCodelet>& result) {
    if (!_interpreter_code_addr || _stub_buffer_offset < 0 || _stub_limit_offset < 0 || _stub_begin_offset < 0
            || _stub_end_offset < 0 || _stub_count_offset < 0 || _codelet_size_offset < 0
            || _codelet_description_offset < 0 || _codelet_bytecode_offset < 0 || _codelet_header_size <= 0) {
        throw std::runtime_error("HotSpot interpreter codelet metadata is unavailable");
    }
    auto flag = JVMFlag::find("CodeEntryAlignment");
    if (!flag) throw std::runtime_error("HotSpot code-entry alignment is unavailable");
    auto alignment = *reinterpret_cast<const unsigned*>(flag->addr());
    if (!alignment || (alignment & (alignment - 1)) || alignment > 4096) throw std::runtime_error("Invalid interpreter code-entry alignment");
    auto queue = *_interpreter_code_addr;
    auto buffer = *reinterpret_cast<const unsigned char**>(queue + _stub_buffer_offset);
    auto limit = *reinterpret_cast<const int*>(queue + _stub_limit_offset);
    auto cursor = *reinterpret_cast<const int*>(queue + _stub_begin_offset);
    auto end = *reinterpret_cast<const int*>(queue + _stub_end_offset);
    auto count = *reinterpret_cast<const int*>(queue + _stub_count_offset);
    result.clear();
    for (int i = 0; i < count; ++i) {
        if (cursor < 0 || cursor >= limit) throw std::runtime_error("Invalid interpreter codelet index");
        auto stub = buffer + cursor;
        auto size = *reinterpret_cast<const int*>(stub + _codelet_size_offset);
        if (size <= _codelet_header_size || size > limit - cursor) throw std::runtime_error("Invalid interpreter codelet size");
        auto first = (reinterpret_cast<std::uintptr_t>(stub + _codelet_header_size) + alignment - 1) & ~std::uintptr_t(alignment - 1);
        if (first >= reinterpret_cast<std::uintptr_t>(stub + size)) throw std::runtime_error("Empty interpreter codelet");
        result.push_back({reinterpret_cast<const unsigned char*>(first),stub + size,
            *reinterpret_cast<const char* const*>(stub + _codelet_description_offset),
            *reinterpret_cast<const int*>(stub + _codelet_bytecode_offset)});
        cursor += size;
        if (cursor == limit && end < limit) cursor = 0;
    }
    if (cursor != end || result.empty()) throw std::runtime_error("Inconsistent interpreter codelet queue");
    std::sort(result.begin(),result.end(),[](const auto& a, const auto& b) {
        return reinterpret_cast<std::uintptr_t>(a.begin) < reinterpret_cast<std::uintptr_t>(b.begin);
    });
}

namespace WindowsProfiler::JavaUnwind {
namespace {
using Add = DWORD (NTAPI*)(void**, PRUNTIME_FUNCTION, DWORD, DWORD, ULONG_PTR, ULONG_PTR);
using Remove = void (NTAPI*)(void*);
Add addTable = nullptr;
Remove removeTable = nullptr;
std::atomic<std::uintptr_t> entryBarrier{0};
Compiled::CodeRange deoptimizationBlob, uncommonTrapBlob;
void noteNonReturningBlob(const char* name,std::uintptr_t begin,std::uintptr_t end) {
    if (streq(name,"DeoptimizationBlob")) deoptimizationBlob = {begin,end};
    else if (streq(name,"UncommonTrapBlob")) uncommonTrapBlob = {begin,end};
}
bool isEntryBarrierName(const char* name) {
    // Stub names of the same generator: JDK25 method_entry_barrier, JDK26
    // "Stub Generator method_entry_barrier_stub" (prefix removed by Profiler),
    // JDK27 "method_entry_barrier_stub (stub gen)". Both normal returns
    // restore RBP/SP; deoptimization leaves the compiled method.
    switch (VM::hotspot_version()) {
        case 25: return streq(name,"method_entry_barrier");
        case 26: return streq(name,"method_entry_barrier_stub");
        case 27: return streq(name,"method_entry_barrier_stub (stub gen)");
        default: return streq(name,"nmethod_entry_barrier");
    }
}
struct Carrier { jclass klass = nullptr; std::uintptr_t metadata = 0; } carrier;

void initializeCarrier() {
    if (carrier.klass) return;
    using Define = jclass (JNICALL*)(JNIEnv*, jclass, const char*, const jbyte*, jsize, jobject, jboolean, int, jobject);
    auto define = reinterpret_cast<Define>(GetProcAddress(reinterpret_cast<HMODULE>(const_cast<char*>(VMStructs::libjvm()->imageBase())), "JVM_LookupDefineClass"));
    // JDK 8 JVMTI may redefine VM-anonymous classes, freeing replaced bytecode.
    if (!define && VM::hotspot_version() < 9) return;
    auto env = VM::jni();
    struct Locals {
        JNIEnv* env; jclass host = nullptr, data = nullptr, unsafeClass = nullptr; jobject unsafe = nullptr; jbyteArray array = nullptr;
        ~Locals() {
            for (jobject local : {static_cast<jobject>(host), static_cast<jobject>(data), static_cast<jobject>(unsafeClass), unsafe, static_cast<jobject>(array)}) {
                if (local) env->DeleteLocalRef(local);
            }
        }
    } locals{env};
    // A strong hidden bootstrap class (JDK 15+) or a VM-anonymous class hosted
    // by Object (JDK 9-14) is unmodifiable; the retained global reference keeps
    // it loaded. Its never-executed method tail stores fixed unwind records.
    std::vector<unsigned char> code{0xb1,0,0,0,
        2,0,10,0x15,0,3,0,0x22,0,10,0,0x54,1,0,0,3,0,2,0,2,0,0x54,2,0,0xb1};
    std::vector<unsigned char> bytes;
    auto u2 = [&](unsigned value) { bytes.push_back(static_cast<unsigned char>(value >> 8)); bytes.push_back(static_cast<unsigned char>(value)); };
    auto u4 = [&](unsigned value) { u2(value >> 16); u2(value); };
    auto utf = [&](const char* value) { bytes.push_back(1); auto size = std::strlen(value); u2(static_cast<unsigned>(size)); bytes.insert(bytes.end(),value,value + size); };
    u4(0xcafebabe); u2(0); u2(49); u2(8);
    utf("java/lang/WinUnwindMetadata"); bytes.push_back(7); u2(1);
    utf("java/lang/Object"); bytes.push_back(7); u2(3);
    utf("data"); utf("()V"); utf("Code");
    u2(0x1030); u2(2); u2(4); u2(0); u2(0); u2(1);
    u2(0xa); u2(5); u2(6); u2(1); u2(7); u4(static_cast<unsigned>(12 + code.size()));
    u2(16); u2(4); u4(static_cast<unsigned>(code.size())); bytes.insert(bytes.end(),code.begin(),code.end());
    u2(0); u2(0); u2(0);
    locals.host = env->FindClass("java/lang/Object");
    if (define) {
        locals.data = define(env, locals.host, "java/lang/WinUnwindMetadata", reinterpret_cast<const jbyte*>(bytes.data()),
            static_cast<jsize>(bytes.size()), nullptr, JNI_FALSE, 6, nullptr); // HIDDEN_CLASS | STRONG_LOADER_LINK
    } else if ((locals.unsafeClass = env->FindClass("sun/misc/Unsafe"))) {
        auto field = env->GetStaticFieldID(locals.unsafeClass, "theUnsafe", "Lsun/misc/Unsafe;");
        auto anonymous = field ? env->GetMethodID(locals.unsafeClass, "defineAnonymousClass", "(Ljava/lang/Class;[B[Ljava/lang/Object;)Ljava/lang/Class;") : nullptr;
        if (anonymous && (locals.unsafe = env->GetStaticObjectField(locals.unsafeClass, field))
                && (locals.array = env->NewByteArray(static_cast<jsize>(bytes.size())))) {
            env->SetByteArrayRegion(locals.array, 0, static_cast<jsize>(bytes.size()), reinterpret_cast<const jbyte*>(bytes.data()));
            locals.data = static_cast<jclass>(env->CallObjectMethod(locals.unsafe, anonymous, locals.host, locals.array, nullptr));
        }
    }
    if (!locals.data || !env->GetStaticMethodID(locals.data,"data","()V")) {
        env->ExceptionDescribe(); env->ExceptionClear();
        throw std::runtime_error("Cannot initialize immutable Java unwind storage");
    }
    auto klass = VMKlass::fromJavaClass(env, locals.data);
    if (klass->methodCount() != 1) throw std::runtime_error("Unexpected Java unwind storage method layout");
    jboolean modifiable = JNI_TRUE;
    if (VM::jvmti()->IsModifiableClass(locals.data, &modifiable) != JVMTI_ERROR_NONE || modifiable) {
        throw std::runtime_error("Java unwind storage must be an unmodifiable class");
    }
    auto data = reinterpret_cast<std::uintptr_t>(klass->methodAt(0)->bytecode());
    if (std::memcmp(reinterpret_cast<const void*>(data), code.data(), code.size()) != 0) throw std::runtime_error("Java unwind storage bytes do not match the class template");
    auto retained = static_cast<jclass>(env->NewGlobalRef(locals.data));
    if (!retained) { env->ExceptionClear(); throw std::runtime_error("Cannot retain Java unwind storage"); }
    carrier = {retained,data + 4};
}
WindowsMutex mutex;
std::atomic<bool> enabled{false};
std::atomic<std::uint64_t> publications{0}, failures{0}, methods{0}, entries{0}, unsupported{0}, active{0};
std::atomic<std::uint64_t> retiredTableBytes{0};
std::atomic<std::uint64_t> vmPages{0};
std::atomic<DWORD> error{0};
std::atomic<bool> errorReady{false};
char errorMessage[256]{};

void failed(const char* message) {
    failures.fetch_add(1);
    if (!errorReady.load(std::memory_order_relaxed)) {
        std::snprintf(errorMessage, sizeof(errorMessage), "%s", message);
        errorReady.store(true, std::memory_order_release);
    }
}

enum class Kind { Stack, Method, Bytecode, Metadata, FramePointer };
struct Rule {
    std::uint32_t returnOffset;
    std::int32_t fpOffset;
    Kind kind = Kind::Stack;
    bool operator==(const Rule&) const = default;
    bool operator<(const Rule& other) const { return std::tie(kind, returnOffset, fpOffset) < std::tie(other.kind, other.returnOffset, other.fpOffset); }
};
constexpr Rule unavailable{UINT32_MAX, -1};
struct Span { DWORD begin, end; Rule rule; bool proven = true; };
struct Function { std::uintptr_t end; std::vector<Span> spans; bool compiled = true; size_t history = CfiHistory::none; };
struct Lifetime { std::uint64_t from, to; };
std::vector<Lifetime> lifetimes;
CfiHistory cfiHistory;
std::atomic<std::uint64_t> metadataRetirements{0}, runtimeStubs{0};
std::vector<VMStructs::InterpreterCodelet> codelets;
std::vector<std::pair<std::uintptr_t,std::uintptr_t>> incompleteInterpreter;
std::uint64_t now() { LARGE_INTEGER value; QueryPerformanceCounter(&value); return value.QuadPart; }
struct Page {
    unsigned char* bytes;
    size_t used = 16;
    size_t capacity;
    bool release;
    explicit Page(unsigned char* bytes, size_t capacity = 65536, bool release = true) : bytes(bytes), capacity(capacity), release(release) {}
    Page(const Page&) = delete;
    Page(Page&& other) noexcept : bytes(std::exchange(other.bytes, nullptr)), used(other.used), capacity(other.capacity), release(other.release) {}
    ~Page() { if (bytes && release) VirtualFree(bytes,0,MEM_RELEASE); }
};
std::uintptr_t rvaEnd(std::uintptr_t base) {
    constexpr std::uintptr_t size = std::uintptr_t{1} << 32;
    if (base > UINTPTR_MAX - size) throw std::runtime_error("Java unwind RVA window overflows pointer width");
    return base + size;
}
// Metadata PCs can contain JVM monitorexit (0xc3), which resembles x86 ret.
// Version 2 omits heuristic epilogue decoding for these data PCs. Code ranges
// also have explicit per-PC rules, so they do not need heuristic native
// epilogue decoding. Code records are followed by the HotSpot handler fields.
std::vector<unsigned char> encode(const Rule& rule) {
    std::vector<unsigned char> data{static_cast<unsigned char>(rule.kind == Kind::Metadata ? 2 : 10),0,0,0};
    auto slot = [&](unsigned char op) { data.push_back(0); data.push_back(op); };
    auto word = [&](std::uint16_t value) {
        data.push_back(static_cast<unsigned char>(value)); data.push_back(static_cast<unsigned char>(value >> 8));
    };
    auto dword = [&](std::uint32_t value) { word(static_cast<std::uint16_t>(value)); word(static_cast<std::uint16_t>(value >> 16)); };
    if (rule.kind == Kind::Method || rule.kind == Kind::Bytecode) {
        int offset = (rule.kind == Kind::Method ? InterpreterFrame::method_offset : InterpreterFrame::bcp_offset()) * 8;
        int scaled = (-offset + 15) / 16;
        if (offset > 0 || scaled > 15) throw std::runtime_error("Interpreter transport slot is outside Windows frame-pointer encoding");
        data[3] = static_cast<unsigned char>((scaled << 4) | 5);
        slot(3);
        if (offset + scaled * 16) slot(2);
    } else if (rule.kind == Kind::Metadata) {
        static_assert(InterpreterFrame::sender_sp_offset == -1);
        data[3] = 0x15;
        slot(3); slot(0x22); slot(0x0a);
        slot(0x54); word(1);
        slot(3); slot(0x12);
        slot(0x54); word(2);
    } else if (rule.kind == Kind::FramePointer) {
        data[3] = 5;
        slot(3); slot(0x50);
    } else if (rule.fpOffset >= 0 && static_cast<std::uint32_t>(rule.fpOffset + 8) == rule.returnOffset) {
        auto allocation = static_cast<std::uint32_t>(rule.fpOffset);
        if (allocation) {
            if (allocation <= 128) slot(static_cast<unsigned char>(((allocation / 8 - 1) << 4) | 2));
            else if (allocation <= 0x7fff8) { slot(1); word(static_cast<std::uint16_t>(allocation / 8)); }
            else { slot(0x11); dword(allocation); }
        }
        slot(0x50);
    } else if (rule.fpOffset >= 0) {
        if (rule.fpOffset <= 0x7fff8) { slot(0x54); word(static_cast<std::uint16_t>(rule.fpOffset / 8)); }
        else { slot(0x55); dword(static_cast<std::uint32_t>(rule.fpOffset)); }
    }
    if (rule.kind == Kind::Stack && rule.returnOffset
            && !(rule.fpOffset >= 0 && static_cast<std::uint32_t>(rule.fpOffset + 8) == rule.returnOffset)) {
        if (rule.returnOffset <= 128) slot(static_cast<unsigned char>(((rule.returnOffset / 8 - 1) << 4) | 2));
        else if (rule.returnOffset <= 0x7fff8) { slot(1); word(static_cast<std::uint16_t>(rule.returnOffset / 8)); }
        else { slot(0x11); dword(rule.returnOffset); }
    }
    data[2] = static_cast<unsigned char>((data.size() - 4) / 2);
    if (data.size() & 3) word(0);
    return data;
}
constexpr std::uintptr_t granule = 65536;
struct Placement { std::uint64_t candidates = 0; DWORD error = 0; };
// Commits the lowest free granule in [first, limit).
unsigned char* allocatePage(std::uintptr_t first, std::uintptr_t limit, Placement& placement) {
    if (first > UINTPTR_MAX - (granule - 1)) return nullptr;
    for (auto cursor = (first + granule - 1) & ~(granule - 1); cursor <= limit && limit - cursor >= granule;) {
        MEMORY_BASIC_INFORMATION region{};
        if (!VirtualQuery(reinterpret_cast<void*>(cursor), &region, sizeof(region))) return nullptr;
        auto next = reinterpret_cast<std::uintptr_t>(region.BaseAddress) + region.RegionSize;
        auto address = (cursor + granule - 1) & ~(granule - 1);
        if (region.State == MEM_FREE && address + granule <= std::min(next, limit)) {
            ++placement.candidates;
            if (auto memory = static_cast<unsigned char*>(VirtualAlloc(reinterpret_cast<void*>(address), granule, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) return memory;
            placement.error = GetLastError();
            cursor = address + granule;
        } else { if (next <= cursor) return nullptr; cursor = next; }
    }
    return nullptr;
}
struct UnwindStorage {
    std::uintptr_t base, end;
    ULONG handler = 0, handlerData = 0;
    bool metadata;
    std::map<Rule, DWORD> infos;
    std::vector<Page> pages;
    UnwindStorage(std::uintptr_t base, std::uintptr_t end, bool metadata) : base(base), end(end), metadata(metadata) {}

    DWORD info(const Rule& rule) {
        if (auto found = infos.find(rule); found != infos.end()) return found->second;
        auto data = encode(rule);
        for (auto value : {handler, handlerData}) for (int shift = 0; shift < 32; shift += 8) data.push_back(static_cast<unsigned char>(value >> shift));
        if (pages.empty() || pages.back().used + data.size() > pages.back().capacity) {
            unsigned char* memory = nullptr;
            size_t capacity = granule;
            bool release = true;
            if (VmStorage::acquire(base,rvaEnd(base),memory,capacity)) {
                release = false; vmPages.fetch_add(1);
            }
            Placement placement;
            if (!memory) memory = allocatePage(end, rvaEnd(base), placement);
            if (!memory) {
                // libgraal's isolate reserves 32 GiB of address space, which can
                // fill the window; jargraal compiles with the same Graal.
                auto libgraal = JVMFlag::find("UseJVMCINativeLibrary"), jvmci = JVMFlag::find("UseJVMCICompiler");
                bool isolate = libgraal && libgraal->get() && jvmci && jvmci->get();
                const char* remedy;
                if (VmStorage::capacity()) remedy = isolate ? "; the WhiteBox buffer is full: use -XX:-UseJVMCINativeLibrary" : "; the WhiteBox buffer is full";
                else if (VmStorage::allocatorMissing()) remedy = isolate ? "; WhiteBox has no code-blob allocator: use -XX:-UseJVMCINativeLibrary" : "; WhiteBox has no code-blob allocator";
                else remedy = isolate ? "; use -XX:-UseJVMCINativeLibrary or -XX:+UnlockDiagnosticVMOptions -XX:+WhiteBoxAPI"
                    : "; use -XX:+UnlockDiagnosticVMOptions -XX:+WhiteBoxAPI";
                char message[256];
                std::snprintf(message, sizeof(message), "No Java unwind storage (code) %p..%p: no free granule within 4 GiB above the code cache (candidates=%llu error=%lu)%s",
                    reinterpret_cast<void*>(base), reinterpret_cast<void*>(end), static_cast<unsigned long long>(placement.candidates), placement.error, remedy);
                throw std::runtime_error(message);
            }
            Page page(memory,capacity,release);
            pages.push_back(std::move(page));
        }
        auto& page = pages.back();
        auto target = page.bytes + page.used;
        std::memcpy(target, data.data(), data.size()); page.used += data.size();
        auto relative = static_cast<DWORD>(reinterpret_cast<std::uintptr_t>(target) - base);
        infos.emplace(rule, relative);
        return relative;
    }
};

// Immutable metadata UNWIND_INFO copies shared by every cluster until stop;
// each page holds one copy at its first record offset.
std::vector<Page> metadataPages;
std::atomic<std::uint64_t> loweredMetadataOrigins{0};
struct MetadataInfo { std::uintptr_t origin; DWORD relative; };
// The RVA origin of a metadata cluster [base, end) is base, or a storage
// granule directly below base: kernel and RtlLookupFunctionEntry lookups accept
// a growable RangeBase below the covered PCs, and the zero gap keeps memory the
// profiler does not own out of the registered range.
MetadataInfo metadataInfo(std::uintptr_t base, std::uintptr_t end) {
    auto data = encode({0,-1,Kind::Metadata});
    auto reaches = [&](std::uintptr_t copy) { return copy >= base && copy <= rvaEnd(base) - data.size(); };
    if (carrier.klass && reaches(carrier.metadata)) return {base,static_cast<DWORD>(carrier.metadata - base)};
    bool lowerable = base >= granule && end - (base - granule) <= UINT32_MAX;
    for (const auto& page : metadataPages) {
        auto copy = reinterpret_cast<std::uintptr_t>(page.bytes) + page.used - data.size();
        if (reaches(copy)) return {base,static_cast<DWORD>(copy - base)};
        if (lowerable && reinterpret_cast<std::uintptr_t>(page.bytes) == base - granule) return {base - granule,static_cast<DWORD>(page.used - data.size())};
    }
    Placement placement;
    auto memory = allocatePage(end, rvaEnd(base), placement);
    auto origin = base;
    if (!memory && lowerable) {
        memory = static_cast<unsigned char*>(VirtualAlloc(reinterpret_cast<void*>(base - granule), granule, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (memory) { origin = base - granule; loweredMetadataOrigins.fetch_add(1); }
    }
    if (!memory) {
        char message[256];
        std::snprintf(message, sizeof(message), "No Java unwind storage (metadata) %p..%p: carrier %p is outside the 4 GiB window, no granule within it is free and the granule below is occupied (candidates=%llu error=%lu)",
            reinterpret_cast<void*>(base), reinterpret_cast<void*>(end), reinterpret_cast<void*>(carrier.metadata),
            static_cast<unsigned long long>(placement.candidates), placement.error);
        throw std::runtime_error(message);
    }
    metadataPages.emplace_back(memory);
    auto& page = metadataPages.back();
    std::memcpy(page.bytes + page.used, data.data(), data.size()); page.used += data.size();
    return {origin,static_cast<DWORD>(reinterpret_cast<std::uintptr_t>(page.bytes) + page.used - data.size() - origin)};
}

struct MetadataRange { std::uintptr_t begin, end; size_t history; };
struct Area : UnwindStorage {
    bool dirty = true, releasing = false, retired = false;
    std::uintptr_t allocationBase;
    size_t lifetime = SIZE_MAX;
    size_t history = CfiHistory::none;
    void* registration = nullptr;
    std::map<std::uintptr_t, Function> functions;
    std::vector<RUNTIME_FUNCTION> table;
    std::vector<std::vector<RUNTIME_FUNCTION>> retiredTables;
    std::vector<MetadataRange> coverage;
    std::vector<size_t> metadataHistories;

    Area(std::uintptr_t base, std::uintptr_t end, const unsigned char* info = nullptr) : UnwindStorage(base,end,info == nullptr), allocationBase(base) {
        if (info) {
            std::memcpy(&handler, info + 4, sizeof(handler));
            std::memcpy(&handlerData, info + 8, sizeof(handlerData));
            history = cfiHistory.addArea(base,end,false);
        } else {
            lifetime = lifetimes.size();
            lifetimes.push_back({now(), UINT64_MAX});
        }
    }
    bool unregister() {
        if (registration) {
            cfiHistory.unpublish(history,now());
            removeTable(registration);
            registration = nullptr; active.fetch_sub(1);
        }
        return true;
    }
    ~Area() {
        unregister();
        if (metadata) for (auto id : metadataHistories) cfiHistory.retireArea(id,now());
    }

    void setFunction(std::uintptr_t begin,Function function) {
        if (auto previous = functions.find(begin); previous != functions.end()) cfiHistory.retire(previous->second.history,now());
        std::vector<ProofSpan> proof;
        for (const auto& span : function.spans) {
            bool proven = span.proven && span.rule != unavailable;
            if (!proof.empty() && proof.back().end == span.begin && proof.back().proven == proven) proof.back().end = span.end;
            else proof.push_back({span.begin,span.end,proven});
        }
        function.history = cfiHistory.addFunction(history,begin,function.end,std::move(proof));
        functions.insert_or_assign(begin,std::move(function));
        dirty = true;
    }

    void addCoverage(std::uintptr_t begin,std::uintptr_t limit) {
        std::vector<std::pair<std::uintptr_t,std::uintptr_t>> added;
        auto cursor = begin;
        for (const auto& range : coverage) {
            if (range.end <= cursor) continue;
            if (range.begin >= limit) break;
            if (range.begin > cursor) added.push_back({cursor,std::min(range.begin,limit)});
            cursor = std::max(cursor,range.end);
            if (cursor >= limit) break;
        }
        if (cursor < limit) added.push_back({cursor,limit});
        metadataHistories.reserve(metadataHistories.size() + added.size());
        coverage.reserve(coverage.size() + added.size());
        for (const auto& [first,last] : added) {
            auto id = cfiHistory.addArea(first,last,true);
            metadataHistories.push_back(id); coverage.push_back({first,last,id}); dirty = true;
        }
        std::sort(coverage.begin(),coverage.end(),[](const auto& a,const auto& b) { return a.begin < b.begin; });
    }
    void ensureCommitted(std::uintptr_t pc) {
        for (const auto& range : coverage) if (pc >= range.begin && pc < range.end) return;
        MEMORY_BASIC_INFORMATION region{};
        if (!VirtualQuery(reinterpret_cast<void*>(pc),&region,sizeof(region)) || region.State != MEM_COMMIT
                || reinterpret_cast<std::uintptr_t>(region.AllocationBase) != allocationBase) throw std::runtime_error("Java metadata is not committed in its allocation");
        addCoverage(std::max(base,reinterpret_cast<std::uintptr_t>(region.BaseAddress)),
            std::min(end,reinterpret_cast<std::uintptr_t>(region.BaseAddress) + region.RegionSize));
    }
    void decommitted(std::uintptr_t begin,std::uintptr_t limit) {
        auto previous = std::move(coverage);
        coverage.clear();
        for (const auto& range : previous) {
            if (range.end <= begin || range.begin >= limit) { coverage.push_back(range); continue; }
            if (range.begin < begin) addCoverage(range.begin,begin);
            if (range.end > limit) addCoverage(limit,range.end);
        }
        std::sort(coverage.begin(),coverage.end(),[](const auto& a,const auto& b) { return a.begin < b.begin; });
        dirty = true;
    }

    void publish() {
        if (!dirty && registration) return;
        std::vector<RUNTIME_FUNCTION> updated;
        auto gap = info({0,-1});
        DWORD cursor = 0;
        for (const auto& [begin, function] : functions) {
            for (const auto& span : function.spans) {
                if (span.rule == unavailable) continue;
                auto first = static_cast<DWORD>(begin - base) + span.begin;
                auto last = static_cast<DWORD>(begin - base) + span.end;
                if (first < cursor) throw std::runtime_error("Overlapping Java unwind ranges");
                if (first > cursor) updated.push_back({cursor, first, gap});
                updated.push_back({first, last, info(span.rule)});
                cursor = last;
            }
        }
        if (cursor < end - base) updated.push_back({cursor, static_cast<DWORD>(end - base), gap});
        if (!unregister()) throw std::runtime_error("Cannot replace a live Java unwind table");
        // Match the runtime publication order: retain the old array through
        // registration of its replacement.
        auto previous = std::move(table);
        table = std::move(updated);
        auto status = addTable(&registration, table.data(), static_cast<DWORD>(table.size()), static_cast<DWORD>(table.size()), base, end);
        if (status) {
            if (!previous.empty()) {
                retiredTableBytes.fetch_add(previous.capacity() * sizeof(RUNTIME_FUNCTION));
                retiredTables.push_back(std::move(previous));
            }
            registration = nullptr; error = status; throw std::runtime_error("Cannot publish the Java ETW growable unwind table");
        }
        auto published = now();
        cfiHistory.publish(history,published);
        for (auto& [begin,function] : functions) cfiHistory.activate(function.history,published);
        active.fetch_add(1); publications.fetch_add(1);
        dirty = false;
    }
};
std::vector<std::unique_ptr<Area>> areas;

struct MetadataCluster {
    std::uintptr_t base, end, origin = 0;
    std::vector<Area*> members;
    std::vector<size_t> histories;
    std::vector<RUNTIME_FUNCTION> table;
    void* registration = nullptr;

    explicit MetadataCluster(std::vector<Area*> members) :
            base(members.front()->base), end(members.back()->end), members(std::move(members)) {}
    ~MetadataCluster() { unregister(); }
    void prepare() {
        bool covered = false;
        for (auto member : members) covered |= !member->coverage.empty();
        if (!covered) return;
        auto [chosen, data] = metadataInfo(base,end);
        origin = chosen;
        for (auto member : members) for (const auto& range : member->coverage) {
            if (range.begin < base || range.end <= range.begin || range.end - origin > UINT32_MAX) {
                throw std::runtime_error("Metadata cluster exceeds the Windows function RVA range");
            }
            table.push_back({static_cast<DWORD>(range.begin - origin),static_cast<DWORD>(range.end - origin),data});
            histories.push_back(range.history);
        }
        for (auto history : histories) cfiHistory.preparePublication(history);
    }
    void unregister() {
        if (!registration) return;
        auto time = now();
        for (auto history : histories) cfiHistory.unpublish(history,time);
        removeTable(registration); registration = nullptr; active.fetch_sub(1);
    }
    void publish() {
        if (registration || table.empty()) return;
        auto status = addTable(&registration,table.data(),static_cast<DWORD>(table.size()),static_cast<DWORD>(table.size()),origin,end);
        if (status) {
            registration = nullptr; error = status;
            throw std::runtime_error("Cannot publish the Java metadata cluster unwind table");
        }
        auto time = now();
        for (auto history : histories) cfiHistory.publish(history,time);
        active.fetch_add(1); publications.fetch_add(1);
    }
    bool intersects(const std::vector<Area*>& candidate) const {
        for (auto member : members) if (std::find(candidate.begin(),candidate.end(),member) != candidate.end()) return true;
        return false;
    }
};
std::vector<std::unique_ptr<MetadataCluster>> metadataClusters, retiredMetadataClusters;

std::vector<std::unique_ptr<MetadataCluster>> suspendMetadata(const std::vector<Area*>& members) {
    std::vector<std::unique_ptr<MetadataCluster>> result;
    result.reserve(metadataClusters.size());
    for (const auto& cluster : metadataClusters) if (cluster->intersects(members)) {
        for (auto history : cluster->histories) cfiHistory.preparePublication(history);
    }
    std::erase_if(metadataClusters,[&](auto& cluster) {
        if (!cluster->intersects(members)) return false;
        cluster->unregister(); result.push_back(std::move(cluster)); return true;
    });
    return result;
}
void restoreMetadata(std::vector<std::unique_ptr<MetadataCluster>>& previous) {
    for (auto& cluster : previous) {
        try { cluster->publish(); }
        catch (const std::exception& exception) { failed(exception.what()); }
        metadataClusters.push_back(std::move(cluster));
    }
    previous.clear();
}
void publishMetadata(bool tolerateUnrepresentable = false) {
    std::vector<Area*> ordered;
    for (auto& area : areas) if (area->metadata && !area->retired) ordered.push_back(area.get());
    std::sort(ordered.begin(),ordered.end(),[](auto a,auto b) { return a->base < b->base; });
    std::vector<std::vector<Area*>> desired;
    for (auto area : ordered) {
        if (desired.empty() || desired.back().back()->end != area->base || area->end - desired.back().front()->base > UINT32_MAX) {
            desired.push_back({area});
        } else desired.back().push_back(area);
    }
    std::vector<std::unique_ptr<MetadataCluster>> prepared;
    // Allocate records and vectors before withdrawing any valid publication.
    for (auto& members : desired) {
        bool unchanged = false;
        for (const auto& cluster : metadataClusters) {
            if (cluster->members != members || (!cluster->registration && !cluster->table.empty())) continue;
            unchanged = std::none_of(members.begin(),members.end(),[](auto member) { return member->dirty; });
            if (unchanged) break;
        }
        if (unchanged) continue;
        try {
            auto cluster = std::make_unique<MetadataCluster>(members);
            cluster->prepare(); prepared.push_back(std::move(cluster));
        } catch (const std::exception& exception) {
            if (!tolerateUnrepresentable) throw;
            failed(exception.what());
        }
    }
    metadataClusters.reserve(metadataClusters.size() + prepared.size());
    retiredMetadataClusters.reserve(retiredMetadataClusters.size() + metadataClusters.size() + prepared.size());
    for (auto& cluster : prepared) {
        auto previous = suspendMetadata(cluster->members);
        try {
            cluster->publish();
            for (auto member : cluster->members) member->dirty = false;
            metadataClusters.push_back(std::move(cluster));
            for (auto& retired : previous) retiredMetadataClusters.push_back(std::move(retired));
        } catch (const std::exception& exception) {
            cluster->unregister();
            restoreMetadata(previous);
            retiredMetadataClusters.push_back(std::move(cluster));
            if (!tolerateUnrepresentable) throw;
            failed(exception.what());
        }
    }
}

Area& areaFor(std::uintptr_t pc) {
    for (auto& area : areas) if (!area->retired && !area->metadata && pc >= area->base && pc < area->end) return *area;
    DWORD64 base = 0;
    auto original = RtlLookupFunctionEntry(pc, &base, nullptr);
    if (!original || original->BeginAddress != 0) throw std::runtime_error("Missing HotSpot code-cache exception registration");
    auto info = reinterpret_cast<const unsigned char*>(base + original->UnwindData);
    if (info[0] != 9 || info[1] || info[2] || info[3]) throw std::runtime_error("Unsupported HotSpot code-cache exception registration");
    areas.push_back(std::make_unique<Area>(base, base + original->EndAddress, info));
    return *areas.back();
}

Area& metadataArea(std::uintptr_t pc) {
    for (auto& area : areas) if (!area->retired && area->metadata && pc >= area->base && pc < area->end) {
        area->ensureCommitted(pc); return *area;
    }
    MEMORY_BASIC_INFORMATION region{};
    if (!VirtualQuery(reinterpret_cast<void*>(pc), &region, sizeof(region)) || region.State != MEM_COMMIT) {
        throw std::runtime_error("Java metadata is not committed memory");
    }
    auto base = reinterpret_cast<std::uintptr_t>(region.AllocationBase);
    auto end = base;
    while (VirtualQuery(reinterpret_cast<void*>(end), &region, sizeof(region)) && reinterpret_cast<std::uintptr_t>(region.AllocationBase) == base) {
        auto next = reinterpret_cast<std::uintptr_t>(region.BaseAddress) + region.RegionSize;
        if (next <= end) throw std::runtime_error("Invalid Java metadata allocation range");
        end = next;
    }
    if (end <= base || end - base > UINT32_MAX) throw std::runtime_error("Java metadata allocation exceeds Windows unwind RVA range");
    auto area = std::make_unique<Area>(base,end);
    for (auto cursor = base; cursor < end;) {
        if (!VirtualQuery(reinterpret_cast<void*>(cursor),&region,sizeof(region))) throw std::runtime_error("Cannot inspect committed Java metadata");
        auto next = reinterpret_cast<std::uintptr_t>(region.BaseAddress) + region.RegionSize;
        if (next <= cursor) throw std::runtime_error("Invalid committed Java metadata range");
        if (region.State == MEM_COMMIT) area->addCoverage(cursor,std::min(next,end));
        cursor = next;
    }
    areas.push_back(std::move(area));
    return *areas.back();
}

std::vector<Span> compiledRules(const void* code, int size, NMethod* method) {
    std::vector<Span> result;
    int words = method->frameSize();
    if (words < 0 || words > 0x8000) return result;
    bool frameless = method->isFrameless();
    Rule body{words == 0 ? 0u : static_cast<DWORD>(words * 8 - 8), words >= 2 ? words * 8 - 16 : -1};
    auto start = reinterpret_cast<std::uintptr_t>(code);
    auto entry = reinterpret_cast<std::uintptr_t>(method->entry());
    auto completeOffset = method->frameCompleteOffset();
    auto complete = reinterpret_cast<std::uintptr_t>(method->code()) + completeOffset;
    // An OSR nmethod has its own entry. C2 poisons the verified entry with INT3,
    // leaving the OSR entry as the only way in; C1 builds the same frame at
    // both entries. JVMCI uses the OSR entry as the verified entry.
    auto osr = method->entryBci() != -1 ? reinterpret_cast<std::uintptr_t>(method->osrEntry()) : entry;
    bool secondary = osr != entry;
    bool poisoned = secondary && static_cast<const unsigned char*>(code)[entry - start] == 0xcc;
    auto prologue = poisoned ? osr : entry;
    bool savedRbp = !frameless && completeOffset >= 0 && prologue >= start && prologue - start < static_cast<size_t>(size)
        && complete >= start && Leaf::savedRbpSlot(static_cast<const unsigned char*>(code),static_cast<size_t>(size),
            prologue - start,complete - start,body.returnOffset);
    // [secondBegin, secondEnd) is C1's OSR prologue; the frame is complete after it.
    size_t secondBegin = 0, secondEnd = 0;
    if (savedRbp && secondary && !poisoned) {
        secondBegin = osr - start;
        secondEnd = Leaf::prologueEnd(static_cast<const unsigned char*>(code),static_cast<size_t>(size),secondBegin,body.returnOffset);
        savedRbp = secondEnd != 0;
    }
    // The typed snapshot admits an OSR nmethod only when its OSR entry is the verified entry.
    if (!savedRbp && entry >= start && entry - start < static_cast<size_t>(size)) {
        Compiled::Handlers::Snapshot snapshot;
        std::vector<Compiled::Span> flow;
        bool proven = false;
        if (method->snapshotUnwindHandlers(code,size,snapshot) == nullptr) {
            Compiled::Layout layout{snapshot.address(),entryBarrier.load(std::memory_order_acquire),
                snapshot.entry(),snapshot.allocation(),snapshot.edges().empty(),true,deoptimizationBlob,uncommonTrapBlob,
                snapshot.unverifiedEntry()};
            proven = Compiled::analyse(snapshot.code().data(),snapshot.code().size(),layout,flow,snapshot.edges(),snapshot.faults());
        }
        if (proven) {
            for (const auto& span : flow) result.push_back({span.begin,span.end,
                span.proven ? Rule{span.returnOffset,span.fpOffset} : unavailable,span.proven});
            return result;
        }
        unsupported.fetch_add(1);
        if (method->hasSingleUnwindEntry()) {
            result.push_back({0,static_cast<DWORD>(size),unavailable,false});
            return result;
        }
    }
    if (frameless) return {{0,static_cast<DWORD>(size),{0,-1,Kind::Stack},false}};
    if (completeOffset < 0) return result;
    // Graal can reserve the conventional RBP slot without writing it. Only a
    // validated leaf path may preserve the live register instead of loading
    // that unused slot; other paths retain the existing frame rules.
    std::vector<Leaf::Span> leaf;
    Leaf::preservedRbp(static_cast<const unsigned char*>(code),static_cast<size_t>(size),body.returnOffset,leaf);
    size_t leafIndex = 0;
    std::vector<unsigned char> bytes(static_cast<size_t>(size) + 16, 0);
    std::memcpy(bytes.data() + 8, code, size);
    std::vector<std::uintptr_t> stack(std::max(words + 2, 4), 0);
    auto initialSP = reinterpret_cast<std::uintptr_t>(stack.data());
    constexpr std::uintptr_t initialFP = 0x12345678;
    StackFrame frame(nullptr);
    for (int offset = 0; offset < size; ++offset) {
        auto pc = reinterpret_cast<std::uintptr_t>(code) + offset;
        auto sp = initialSP, fp = initialFP;
        Rule rule = body;
        bool proven = savedRbp;
        while (leafIndex < leaf.size() && offset >= leaf[leafIndex].end) ++leafIndex;
        if (poisoned ? pc < complete : static_cast<size_t>(offset) >= secondBegin && static_cast<size_t>(offset) < secondEnd) {
            // Unreachable poisoned code or an OSR prologue; upstream prologue
            // rules are relative to the verified entry.
            rule = unavailable; proven = false;
        } else if (leafIndex < leaf.size() && offset >= leaf[leafIndex].begin) {
            rule = {leaf[leafIndex].returnOffset,-1};
            proven = true;
        } else if (pc < complete) {
            if (!frame.unwindPrologue(method, pc, sp, fp)) rule = unavailable;
            else rule = {static_cast<DWORD>(sp - initialSP - 8), fp == initialFP ? -1 : static_cast<int>(sp - initialSP - 16)};
        } else {
            pc = reinterpret_cast<std::uintptr_t>(bytes.data() + 8 + offset);
            if (frame.unwindEpilogue(method, pc, sp, fp)) {
                rule = {static_cast<DWORD>(sp - initialSP - 8), fp == initialFP ? -1 : static_cast<int>(sp - initialSP - 16)};
            }
        }
        if (result.empty() || result.back().rule != rule || result.back().proven != proven) result.push_back({static_cast<DWORD>(offset), static_cast<DWORD>(offset + 1), rule,proven});
        else result.back().end++;
    }
    return result;
}

// An unframed stub's entry bytes alone give no rule. Its proof must not
// depend on entries the VM does not report: every byte is a reached
// instruction or trap padding, so no unreached code can enter elsewhere. A
// runtime stub has one entry and a declared frame. A stub in a shared buffer
// may still be entered at a reached instruction, so each one must keep the
// entry frame: RSP at the return address and RBP unchanged.
std::vector<Span> stubRules(const unsigned char* code, int size, NMethod* blob, bool coarse) {
    if (!blob || !blob->contains(code) || !blob->contains(code + size - 1)
            || (coarse && (blob->isNMethod() || blob->frameSize() <= 0 || blob->frameSize() > 0x8000))) return {};
    Compiled::Layout layout{reinterpret_cast<std::uintptr_t>(code),0,0,coarse ? static_cast<std::uint32_t>(blob->frameSize() * 8 - 8) : 0u,
        true,true,deoptimizationBlob,uncommonTrapBlob};
    std::vector<Compiled::Span> flow;
    std::vector<std::uint32_t> reachable;
    if (!Compiled::analyse(code,static_cast<size_t>(size),layout,flow,{},{},&reachable)) return {};
    std::vector<bool> covered(static_cast<size_t>(size));
    for (auto start : reachable) {
        auto length = InstructionDecoder::length(code + start,static_cast<size_t>(size) - start);
        std::fill_n(covered.begin() + start,length,true);
    }
    for (int offset = 0; offset < size; ++offset)
        if (!covered[offset] && code[offset] != 0xf4 && code[offset] != 0xcc) return {};
    std::vector<Span> result;
    for (const auto& span : flow) {
        auto first = std::lower_bound(reachable.begin(),reachable.end(),span.begin);
        bool reached = first != reachable.end() && *first < span.end;
        if (!coarse && reached && (!span.proven || span.returnOffset || span.fpOffset != -1)) return {};
        result.push_back({span.begin,span.end,span.proven ? Rule{span.returnOffset,span.fpOffset} : unavailable,span.proven});
    }
    return result;
}

struct InstructionPattern { size_t begin, end; };
InstructionPattern uniquePattern(const VMStructs::InterpreterCodelet& codelet, size_t first, const char* stage,
        std::initializer_list<std::initializer_list<unsigned char>> alternatives, const char* category = "interpreter") {
    auto size = static_cast<size_t>(codelet.end - codelet.begin);
    InstructionPattern found{size,size};
    for (const auto& pattern : alternatives) {
        for (size_t offset = first; offset + pattern.size() <= size; ++offset) {
            if (std::memcmp(codelet.begin + offset,pattern.begin(),pattern.size()) != 0) continue;
            if (found.begin != size) throw std::runtime_error(std::string("Ambiguous ") + category + " " + stage + " in " + codelet.description);
            found = {offset,offset + pattern.size()};
        }
    }
    if (found.begin == size) throw std::runtime_error(std::string("Unsupported ") + category + " " + stage + " in " + codelet.description);
    return found;
}

std::vector<Span> interpreterRules(std::uintptr_t begin, std::uintptr_t end) {
    std::vector<Span> spans;
    for (const auto& codelet : codelets) {
        auto base = reinterpret_cast<std::uintptr_t>(codelet.begin);
        auto limit = reinterpret_cast<std::uintptr_t>(codelet.end);
        if (base < begin || limit > end) throw std::runtime_error("Interpreter codelet crosses the generated-code range");
        auto size = static_cast<size_t>(limit - base);
        std::string_view name(codelet.description);
        auto append = [&](size_t first, size_t last, Rule rule) {
            if (first < last) spans.push_back({static_cast<DWORD>(base - begin + first),static_cast<DWORD>(base - begin + last),rule});
        };
        bool methodEntry = name.find("method entry point") != std::string_view::npos;
        bool normal = methodEntry && (name.ends_with("(kind = zerolocals)") || name.ends_with("(kind = zerolocals_synchronized)"));
        bool native = methodEntry && (name.ends_with("(kind = native)") || name.ends_with("(kind = native_synchronized)"));
        if (normal || native) {
            // generate_fixed_frame saves sender SP before Method*, and saves
            // the bytecode pointer later. Each stage needs a distinct rule.
            auto fixed = uniquePattern(codelet,0,"frame anchor",{{0x50,0x55,0x48,0x8b,0xec,0x41,0x55},{0x50,0x55,0x48,0x89,0xe5,0x41,0x55}});
            auto methodOffset = VMMethod::constMethodOffset(), codeOffset = VMMethod::constMethodSize();
            if (methodOffset < 0 || methodOffset > 127 || codeOffset < 0 || codeOffset > 127) throw std::runtime_error("Unsupported interpreter metadata displacement");
            auto md = static_cast<unsigned char>(methodOffset), cd = static_cast<unsigned char>(codeOffset);
            auto method = uniquePattern(codelet,fixed.end,"Method save",{
                {0x68,0,0,0,0,0x53},{0x6a,0,0x53},
                {0x68,0,0,0,0,0x4c,0x8b,0x6b,md,0x4d,0x8d,0x6d,cd,0x53},
                {0x6a,0,0x4c,0x8b,0x6b,md,0x4d,0x8d,0x6d,cd,0x53}});
            auto frame = fixed.begin + 5;
            append(0,frame,{0,-1,Kind::Bytecode});
            incompleteInterpreter.emplace_back(base,base + frame);
            append(frame,fixed.end,unavailable);
            append(fixed.end,method.end,{0,-1,Kind::Metadata});
            if (normal) {
                auto initial = static_cast<unsigned char>(InterpreterFrame::bcp_offset() - 1);
                auto bcp = uniquePattern(codelet,method.end,"bytecode save",{
                    {0x41,0x55,0x68,initial,0xff,0xff,0xff},{0x41,0x55,0x6a,initial},
                    {0x41,0x55,0x68,0,0,0,0,0x48,0x89,0x24,0x24},
                    {0x41,0x55,0x68,0,0,0,0,0x48,0x89,0x64,0x24,0},
                    {0x41,0x55,0x6a,0,0x48,0x89,0x24,0x24},
                    {0x41,0x55,0x6a,0,0x48,0x89,0x64,0x24,0}});
                append(method.end,bcp.begin + 2,{0,-1,Kind::Method});
                append(bcp.begin + 2,size,{0,-1,Kind::Bytecode});
            } else append(method.end,size,{0,-1,Kind::Method});
        } else if (name.find("method entry point") != std::string_view::npos && name != "method entry point (kind = abstract)") {
            // Intrinsic entries have no interpreter frame. Retain their
            // callers while reporting the unavailable Java leaf explicitly.
            append(0,size,{0,-1,Kind::Stack});
            incompleteInterpreter.emplace_back(base,limit);
        } else {
            auto nativeHelper = name.find("native") != std::string_view::npos || name == "slow signature handler";
            append(0,size,{0,-1,nativeHelper ? Kind::Method : Kind::Bytecode});
        }
    }
    return spans;
}

void publishLocked() {
    std::uint64_t totalMethods = 0, totalEntries = 0;
    publishMetadata();
    for (const auto& cluster : metadataClusters) if (cluster->registration) totalEntries += cluster->table.size();
    for (auto& area : areas) {
        if (area->retired || area->metadata) continue;
        area->publish();
        totalMethods += area->functions.size();
        totalEntries += area->table.size();
    }
    methods = totalMethods; entries = totalEntries;
}

template<class Call> BOOL releaseMetadata(const void* address, SIZE_T size, DWORD type, bool unmap, Call invoke) {
    bool releases = unmap || (type & MEM_RELEASE) != 0;
    if ((!releases && !(type & MEM_DECOMMIT)) || !enabled.load(std::memory_order_acquire)) return invoke();
    auto incomingError = GetLastError();
    std::unique_lock lock(mutex);
    Imports::Depth depth(Imports::allocation_depth);
    MEMORY_BASIC_INFORMATION region{};
    auto allocation = VirtualQuery(address, &region, sizeof(region)) ? reinterpret_cast<std::uintptr_t>(region.AllocationBase) : 0;
    auto time = now();
    auto failuresBefore = failures.load(std::memory_order_relaxed);
    bool invoked = false;
    BOOL result = FALSE;
    DWORD resultError = incomingError;
    std::vector<std::unique_ptr<MetadataCluster>> previous;
    auto retire = [&](Area& area,std::uint64_t returned) {
        lifetimes[area.lifetime].to = time;
        for (auto id : area.metadataHistories) cfiHistory.retireArea(id,returned);
        area.coverage.clear(); area.retired = true; area.releasing = false;
        metadataRetirements.fetch_add(1);
    };
    try {
        std::vector<Area*> affected;
        affected.reserve(areas.size());
        for (auto& area : areas) if (!area->retired && area->metadata && area->allocationBase == allocation) affected.push_back(area.get());
        if (!affected.empty()) {
            retiredMetadataClusters.reserve(retiredMetadataClusters.size() + metadataClusters.size());
            previous = suspendMetadata(affected);
            SetLastError(incomingError); result = invoke(); invoked = true; resultError = GetLastError();
            auto returned = now();
            if (!result) {
                restoreMetadata(previous);
            } else {
                SYSTEM_INFO system{}; GetSystemInfo(&system);
                auto mask = std::uintptr_t(system.dwPageSize - 1);
                auto first = reinterpret_cast<std::uintptr_t>(address) & ~mask;
                for (auto area : affected) {
                    if (releases) retire(*area,returned);
                    else {
                        auto last = area->end;
                        if (size) {
                            auto start = reinterpret_cast<std::uintptr_t>(address);
                            if (size > UINTPTR_MAX - start || start + size > UINTPTR_MAX - mask) throw std::runtime_error("Metadata decommit range overflows pointer width");
                            last = (start + size + mask) & ~mask;
                        }
                        area->decommitted(std::max(first,area->base),std::min(last,area->end));
                    }
                }
                for (auto& old : previous) retiredMetadataClusters.push_back(std::move(old));
                previous.clear();
                publishMetadata(true);
            }
        } else {
            SetLastError(incomingError); result = invoke(); invoked = true; resultError = GetLastError();
        }
    } catch (const std::exception& exception) {
        failed(exception.what());
        // A tracking/allocation failure must never leave an OS range claiming
        // storage that the JVM is about to free or has already released.
        for (auto& cluster : metadataClusters) cluster->unregister();
        if (!invoked) { SetLastError(incomingError); result = invoke(); resultError = GetLastError(); }
        if (result && releases) {
            auto returned = now();
            for (auto& area : areas) if (!area->retired && area->metadata && area->allocationBase == allocation) retire(*area,returned);
        }
        for (auto& old : previous) if (old) retiredMetadataClusters.push_back(std::move(old));
    }
    bool report = failures.load(std::memory_order_relaxed) != failuresBefore;
    lock.unlock();
    if (report) Log::error("Java metadata unwind tracking failed: %s",firstError());
    SetLastError(resultError);
    return result;
}
struct FreePolicy {
    static BOOL invoke(decltype(&VirtualFree) original, LPVOID address, SIZE_T size, DWORD type) {
        return releaseMetadata(address,size,type,false,[&] { return original(address,size,type); });
    }
};
struct UnmapPolicy {
    static BOOL invoke(decltype(&UnmapViewOfFile) original, LPCVOID address) {
        return releaseMetadata(address,0,0,true,[&] { return original(address); });
    }
};
using FreeHooks = Imports::FunctionHooks<FreePolicy, decltype(&VirtualFree)>;
using UnmapHooks = Imports::FunctionHooks<UnmapPolicy, decltype(&UnmapViewOfFile)>;
void installMemoryHooks() {
    std::lock_guard guard(Imports::import_mutex);
    auto jvm = reinterpret_cast<HMODULE>(const_cast<char*>(VMStructs::libjvm()->imageBase()));
    auto patched = Imports::patch_module(jvm, [](std::string_view library, std::string_view name, void* original) -> void* {
        if (!Imports::windows_library(library)) return nullptr;
        if (name == "VirtualFree") return Imports::import_replacement<FreeHooks>(original, true);
        if (name == "UnmapViewOfFile") return Imports::import_replacement<UnmapHooks>(original, true);
        return nullptr;
    });
    if (!patched && FreeHooks::count.load() == 0) throw std::runtime_error("Cannot observe JVM metadata memory release");
}
}

Error start() {
    stop();
    if (!areas.empty()) return Error("Prior Java unwind registrations could not be retired; restart the target");
    publications = 0; failures = 0; methods = 0; entries = 0; unsupported = 0; error = 0; errorReady = false;
    retiredTableBytes = 0; vmPages = 0;
    metadataRetirements = 0; runtimeStubs = 0; loweredMetadataOrigins = 0; lifetimes.clear();
    entryBarrier.store(0,std::memory_order_release);
    deoptimizationBlob = {}; uncommonTrapBlob = {};
    if (VM::hotspot_version() == 0 || !VMStructs::hasStackStructs() || !VMStructs::hasClassMethods()) return Error("ETW Java unwinding requires HotSpot x86-64 VMStructs");
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    addTable = reinterpret_cast<Add>(GetProcAddress(ntdll, "RtlAddGrowableFunctionTable"));
    removeTable = reinterpret_cast<Remove>(GetProcAddress(ntdll, "RtlDeleteGrowableFunctionTable"));
    if (!addTable || !removeTable) return Error("Windows growable unwind tables are unavailable");
    try {
        initializeCarrier(); VmStorage::initialize(); VmStorage::reset(); installMemoryHooks();
        std::lock_guard lock(mutex);
        if (carrier.klass) metadataArea(carrier.metadata);
        VMStructs::snapshotInterpreterCodelets(codelets); incompleteInterpreter.clear();
        std::vector<CodeBlob> stubs;
        Profiler::instance()->snapshotRuntimeStubs(stubs);
        for (const auto& stub : stubs) {
            if (isEntryBarrierName(stub._name)) entryBarrier.store(reinterpret_cast<std::uintptr_t>(stub._start),std::memory_order_release);
            noteNonReturningBlob(stub._name,reinterpret_cast<std::uintptr_t>(stub._start),reinterpret_cast<std::uintptr_t>(stub._end));
        }
    }
    catch (const std::exception& exception) { failed(exception.what()); return Error(firstError()); }
    enabled = true;
    return Error::OK;
}
void stop() {
    std::lock_guard lock(mutex);
    metadataClusters.clear(); retiredMetadataClusters.clear(); metadataPages.clear();
    std::erase_if(areas, [](const std::unique_ptr<Area>& area) { return area->unregister(); });
    enabled = !areas.empty();
    if (areas.empty()) cfiHistory.clear();
}
void compiled(const void* code, int size, NMethod* method, bool publishNow) {
    std::lock_guard lock(mutex);
    if (!enabled) return;
    try {
        auto spans = compiledRules(code, size, method);
        if (spans.empty()) { unsupported.fetch_add(1); return; }
        auto begin = reinterpret_cast<std::uintptr_t>(code);
        auto& area = areaFor(begin);
        if (begin + size > area.end) throw std::runtime_error("Compiled Java method crosses its unwind area");
        area.setFunction(begin,Function{begin + size,std::move(spans)});
        if (publishNow) publishLocked();
    } catch (const std::exception& exception) { failed(exception.what()); throw; }
      catch (...) { failed("Unknown Java unwind metadata failure"); throw; }
}
void unloaded(const void* code, bool publishNow,std::uint64_t timestamp) {
    std::lock_guard lock(mutex);
    if (!enabled) return;
    try {
        auto begin = reinterpret_cast<std::uintptr_t>(code);
        for (auto& area : areas) if (!area->retired && !area->metadata) if (auto found = area->functions.find(begin); found != area->functions.end()) {
            // Delete the OS registration before the JVM can reuse this address.
            // HotSpot's separate exception registration remains installed.
            cfiHistory.retire(found->second.history,timestamp);
            if (!area->unregister()) throw std::runtime_error("Cannot retire Java code before address reuse");
            area->functions.erase(found);
            area->dirty = true;
            if (publishNow) publishLocked();
            return;
        }
    } catch (const std::exception& exception) { failed(exception.what()); }
      catch (...) { failed("Unknown Java unwind retirement failure"); }
}
Metadata metadata(const void* method, const void* bytecode, int size, bool publishNow) {
    std::lock_guard lock(mutex);
    try {
        auto address = reinterpret_cast<std::uintptr_t>(method);
        auto& owner = metadataArea(address);
        size_t bytecodeLife = SIZE_MAX;
        if (size > 0) {
            auto begin = reinterpret_cast<std::uintptr_t>(bytecode);
            auto& code = metadataArea(begin);
            if (begin + size > code.end) throw std::runtime_error("Java bytecode crosses its metadata allocation");
            bytecodeLife = code.lifetime;
        }
        if (publishNow) publishLocked();
        return {owner.lifetime, bytecodeLife};
    } catch (const std::exception& exception) { failed(exception.what()); throw; }
      catch (...) { failed("Cannot register Java metadata unwind memory"); throw; }
}
bool metadataAlive(size_t lifetime, std::uint64_t time) {
    std::lock_guard lock(mutex);
    return lifetime < lifetimes.size() && time >= lifetimes[lifetime].from && time < lifetimes[lifetime].to;
}
void generated(const void* code, int size, const char* name, bool publishNow) {
    std::lock_guard lock(mutex);
    if (!enabled || size <= 0) return;
    try {
        auto begin = reinterpret_cast<std::uintptr_t>(code), end = begin + size;
        if (isEntryBarrierName(name)) entryBarrier.store(begin,std::memory_order_release);
        noteNonReturningBlob(name,begin,end);
        auto interpreter = std::strcmp(name, "Interpreter") == 0;
        auto bytes = static_cast<const unsigned char*>(code);
        auto adapter = std::strcmp(name, "I2C/C2I adapters") == 0;
        size_t adapterEnd = 0;
        if (adapter) {
            // SharedRuntime::generate_i2c2i_adapters emits i2c first. That
            // frameless path changes RSP, but preserves its interpreter
            // caller's RBP until the final move-Method / jump-target pair.
            constexpr unsigned char entry[]{0x4c,0x8b,0xdc,0x58}; // mov r11,rsp; pop rax
            if (size < sizeof(entry) || std::memcmp(bytes,entry,sizeof(entry)) != 0) {
                unsupported.fetch_add(1);
                return;
            }
            VMStructs::InterpreterCodelet range{bytes,bytes + size,name,0};
            adapterEnd = uniquePattern(range,sizeof(entry),"i2c tail",{
                {0x48,0x8b,0xc3,0x41,0xff,0xe3},{0x48,0x89,0xd8,0x41,0xff,0xe3}},"adapter").end;
            end = begin + adapterEnd;
        }
        bool framed = size >= 4 && bytes[0] == 0x55 && bytes[1] == 0x48
            && ((bytes[2] == 0x8b && bytes[3] == 0xec) || (bytes[2] == 0x89 && bytes[3] == 0xe5));
        auto blob = CodeHeap::findNMethod(code);
        // A coarse buffer can contain several procedures. Framed runtime
        // blobs declare a real frame and can use the same entry rules as
        // fine runtime-stub records.
        bool coarse = blob && std::strcmp(blob->name(), name) == 0;
        bool inherited = blob && blob->frameSize() > 0 &&
            (startsWith(name,"forward_exception") || (coarse && startsWith(name,"C1 Runtime forward_exception")));
        bool analysed = !interpreter && !adapter && !framed && !inherited;
        if (!interpreter && !adapter && !analysed && coarse && (blob->frameSize() <= 0 || blob->isNMethod())) return;
        auto& area = areaFor(begin);
        for (const auto& [start, function] : area.functions) {
            if (start < end && function.end > begin) return;
        }
        std::vector<Span> spans;
        if (interpreter) spans = interpreterRules(begin,end);
        else if (adapter) spans.push_back({0,static_cast<DWORD>(adapterEnd),{0,-1,Kind::Bytecode}});
        else if (analysed) {
            spans = stubRules(bytes,size,blob,coarse);
            if (spans.empty()) return;
        } else {
            CONTEXT context{};
            std::uintptr_t stack[64]{};
            auto initialSP = reinterpret_cast<std::uintptr_t>(stack + 8);
            auto initialFP = reinterpret_cast<std::uintptr_t>(stack + 32);
            context.Rsp = initialSP;
            StackFrame frame(&context);
            for (int offset = 0; offset < size; ++offset) {
                auto pc = begin + offset, sp = initialSP, fp = initialFP;
                Rule rule = unavailable;
                if (inherited) {
                    // Runtime1 forwards exceptions with its caller's saved
                    // register frame still installed, without another enter.
                    rule = bytes[offset] == 0xc3 ? Rule{0,-1} : Rule{0,-1,Kind::FramePointer};
                } else if (frame.unwindStub(reinterpret_cast<instruction_t*>(const_cast<void*>(code)), name, pc, sp, fp)) {
                    rule = fp != initialFP ? Rule{0,-1,Kind::FramePointer}
                        : Rule{static_cast<DWORD>(sp - initialSP - 8),-1};
                }
                if (spans.empty() || spans.back().rule != rule) spans.push_back({static_cast<DWORD>(offset), static_cast<DWORD>(offset + 1), rule});
                else spans.back().end++;
            }
        }
        area.setFunction(begin,Function{end,std::move(spans),false});
        runtimeStubs.fetch_add(1);
        if (publishNow) publishLocked();
    } catch (const std::exception& exception) { failed(exception.what()); throw; }
      catch (...) { failed("Cannot describe JVM generated-code frames"); throw; }
}
bool publish() {
    std::lock_guard lock(mutex);
    try { publishLocked(); return true; }
    catch (const std::exception& exception) { failed(exception.what()); return false; }
    catch (...) { failed("Unknown Java unwind publication failure"); return false; }
}
const char* firstError() { return errorReady.load(std::memory_order_acquire) ? errorMessage : nullptr; }
bool incomplete(std::uint64_t pc) {
    std::lock_guard lock(mutex);
    auto found = std::upper_bound(incompleteInterpreter.begin(),incompleteInterpreter.end(),pc,
        [](std::uint64_t address, const auto& range) { return address < range.first; });
    return found != incompleteInterpreter.begin() && pc < (found - 1)->second;
}
Certainty certainty(std::uint64_t pc,std::uint64_t timestamp,bool knownManaged,bool metadataDecoded) {
    std::lock_guard lock(mutex);
    return cfiHistory.certainty(pc,timestamp,knownManaged,metadataDecoded);
}
void writeMetrics(Writer& out) {
    std::lock_guard lock(mutex);
    out << "windows_java_unwind_publications " << u64(publications.load()) << '\n';
    out << "windows_java_unwind_failures " << u64(failures.load()) << '\n';
    out << "windows_java_unwind_methods " << u64(methods.load()) << '\n';
    out << "windows_java_unwind_entries " << u64(entries.load()) << '\n';
    out << "windows_java_unwind_unsupported " << u64(unsupported.load()) << '\n';
    out << "windows_java_unwind_active_tables " << u64(active.load()) << '\n';
    out << "windows_java_unwind_error " << u64(error.load()) << '\n';
    out << "windows_java_unwind_metadata_retirements " << u64(metadataRetirements.load()) << '\n';
    out << "windows_java_unwind_metadata_lowered_origins " << u64(loweredMetadataOrigins.load()) << '\n';
    out << "windows_java_unwind_runtime_stubs " << u64(runtimeStubs.load()) << '\n';
    out << "windows_java_unwind_entry_barrier_known " << static_cast<u64>(entryBarrier.load(std::memory_order_acquire) != 0) << '\n';
    out << "windows_java_unwind_codelets " << u64(codelets.size()) << '\n';
    out << "windows_java_unwind_code_cache_pages " << u64(vmPages.load()) << '\n';
    out << "windows_java_unwind_code_cache_bytes " << u64(VmStorage::capacity()) << '\n';
    out << "windows_java_unwind_vm_storage " << u64(carrier.klass != nullptr) << '\n';
    out << "windows_java_unwind_retired_table_bytes_peak " << u64(retiredTableBytes.load()) << '\n';
    if (auto message = firstError()) out << "windows_java_unwind_first_error " << message << '\n';
}
}
