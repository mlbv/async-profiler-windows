/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include <windows.h>
#include <cpuid.h>
#include <algorithm>
#include <array>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "windowsInstructionDecoder.h"
using namespace WindowsProfiler::InstructionDecoder;
static size_t checkedCopy(void* destination, const void* source, size_t readable, size_t* written, void** target) {
    Relocation result;
    if (!relocate(destination, MAX_RELOCATED_BYTES, source, readable, result)) return 0;
    *written = result.destinationBytes; *target = const_cast<void*>(result.branchTarget); return result.sourceBytes;
}
static void require(bool condition, const char* message) {
    if (!condition) { std::fprintf(stderr, "%s\n", message); std::exit(1); }
}
template<class T> static T read(const unsigned char* at) { T result; std::memcpy(&result, at, sizeof(result)); return result; }
static unsigned boundaryChecks = 0;
static void checkBoundary(const std::vector<unsigned char>& code, size_t expected, unsigned char* guardedEnd) {
    std::array<unsigned char, 32> padded;
    padded.fill(0x90);
    std::memcpy(padded.data(), code.data(), code.size());
    auto at = guardedEnd - code.size();
    std::memcpy(at, code.data(), code.size());
    for (auto source : {at, padded.data()}) {
        SetLastError(0x12345);
        require(length(source, code.size()) == expected, "Exact instruction boundary changed");
        require(GetLastError() == 0x12345, "Length changed LastError");
        ++boundaryChecks;
        if (expected) for (size_t available = 0; available < code.size(); ++available) {
            require(!length(source, available), "Truncated instruction accepted");
            ++boundaryChecks;
        }
    }
    require(length(padded.data(), MAX_INSTRUCTION_BYTES) == expected, "Following instruction changed boundary");
    ++boundaryChecks;
}
static unsigned evexChecks = 0, evexRangeChecks = 0;
static void evexAccepted(const std::vector<unsigned char>& code,unsigned char* source,
        unsigned char* destination,unsigned char* guardedEnd) {
    checkBoundary(code,code.size(),guardedEnd);
    std::memcpy(source,code.data(),code.size());
    const bool rip = (code[5] & 0xc7) == 0x05;
    for (auto at : {source,guardedEnd - code.size()}) {
        Relocation result{17,19,reinterpret_cast<void*>(1)};
        SetLastError(0x12345);
        std::memset(destination,0xa5,MAX_RELOCATED_BYTES);
        require(relocate(destination,MAX_RELOCATED_BYTES,at,code.size(),result)
            && result.sourceBytes == code.size() && result.destinationBytes == code.size()
            && !result.branchTarget,"Certified EVEX relocation rejected or changed size/class");
        require(GetLastError() == 0x12345,"EVEX relocation changed LastError");
        require(std::memcmp(at,code.data(),code.size()) == 0,"EVEX relocation changed source bytes");
        if (rip) {
            auto originalTarget = reinterpret_cast<std::intptr_t>(at) + code.size() + read<LONG>(at + 6);
            auto relocatedTarget = reinterpret_cast<std::intptr_t>(destination) + code.size() + read<LONG>(destination + 6);
            require(originalTarget == relocatedTarget && !std::memcmp(destination,code.data(),6),
                "EVEX RIP target or prefix changed");
        } else require(!std::memcmp(destination,code.data(),code.size()),"EVEX register/SIB/compressed displacement changed");
        for (size_t index = code.size(); index < MAX_RELOCATED_BYTES; ++index)
            require(destination[index] == 0xa5,"EVEX relocation wrote past its instruction");
        ++evexChecks;
    }
    for (size_t available = 0; available < code.size(); ++available) {
        Relocation result{17,19,reinterpret_cast<void*>(1)};
        std::memset(destination,0xa5,MAX_RELOCATED_BYTES);
        auto partial = guardedEnd - available;
        std::memcpy(partial,code.data(),available);
        require(!relocate(destination,MAX_RELOCATED_BYTES,partial,available,result)
            && result.sourceBytes == 17 && result.destinationBytes == 19 && result.branchTarget == reinterpret_cast<void*>(1),
            "Truncated EVEX relocation accepted or changed output");
        for (unsigned index = 0; index < MAX_RELOCATED_BYTES; ++index)
            require(destination[index] == 0xa5,"Truncated EVEX modified destination");
        ++evexChecks;
    }
}
static void evexRejected(const std::vector<unsigned char>& code,unsigned char* destination,unsigned char* guardedEnd) {
    checkBoundary(code,0,guardedEnd);
    Relocation result{17,19,reinterpret_cast<void*>(1)};
    std::memset(destination,0xa5,MAX_RELOCATED_BYTES);
    SetLastError(0x12345);
    require(!relocate(destination,MAX_RELOCATED_BYTES,guardedEnd - code.size(),code.size(),result)
        && result.sourceBytes == 17 && result.destinationBytes == 19 && result.branchTarget == reinterpret_cast<void*>(1)
        && GetLastError() == 0x12345,"Unsupported EVEX accepted or changed result/error");
    for (unsigned index = 0; index < MAX_RELOCATED_BYTES; ++index)
        require(destination[index] == 0xa5,"Unsupported EVEX modified destination");
    ++evexChecks;
}
static void evex(unsigned char* source,unsigned char* destination,unsigned char* guardedEnd,unsigned char* distant) {
    for (const auto& code : {
            std::vector<unsigned char>{0x62,0xf1,0xff,0x08,0x10,0x05,0xad,0xff,0xff,0xff},
            {0x62,0xd1,0xff,0x08,0x59,0x4a,0x10},
            {0x62,0xf1,0xf7,0x08,0x58,0xca},
            {0x62,0xf1,0xff,0x08,0x11,0x44,0x24,0x06}})
        evexAccepted(code,source,destination,guardedEnd);
    for (unsigned extension = 0; extension < 16; ++extension) {
        for (auto opcode : {0x10u,0x11u,0x58u,0x59u}) {
            for (auto modrm : {0x00u,0x45u,0x84u,0xcau}) {
                std::vector<unsigned char> code{0x62,static_cast<unsigned char>((extension << 4) | 1),
                    0xff,0x08,static_cast<unsigned char>(opcode),static_cast<unsigned char>(modrm)};
                if (modrm == 0x45) code.push_back(0x80);
                if (modrm == 0x84) code.insert(code.end(),{0x65,0x81,0,0,0x80});
                if (modrm == 0xca && opcode <= 0x11) evexRejected(code,destination,guardedEnd);
                else evexAccepted(code,source,destination,guardedEnd);
            }
        }
    }
    for (unsigned sib = 0; sib < 256; ++sib) for (unsigned mode = 0; mode < 3; ++mode) {
        std::vector<unsigned char> code{0x62,0x81,0xff,0x08,0x11,
            static_cast<unsigned char>((mode << 6) | 4),static_cast<unsigned char>(sib)};
        if (mode == 1) code.push_back(sib & 1 ? 0x80 : 0x7f);
        if (mode == 2 || (!mode && (sib & 7) == 5)) code.insert(code.end(),{0x81,0,0,0x80});
        evexAccepted(code,source,destination,guardedEnd);
    }
    for (unsigned vvvv = 0; vvvv < 16; ++vvvv) for (auto opcode : {0x10u,0x11u,0x58u,0x59u}) {
        std::vector<unsigned char> code{0x62,0x01,static_cast<unsigned char>(0x87 | (vvvv << 3)),
            0x08,static_cast<unsigned char>(opcode),0x00};
        if (opcode <= 0x11 && vvvv != 15) evexRejected(code,destination,guardedEnd);
        else evexAccepted(code,source,destination,guardedEnd);
    }
    for (unsigned extension = 0; extension < 16; ++extension) for (unsigned vvvv = 0; vvvv < 16; ++vvvv) {
        for (auto opcode : {0x99u,0xa9u,0xb9u}) for (auto modrm : {0xe5u,0x00u,0x6cu,0xa4u,0x05u}) {
            std::vector<unsigned char> code{0x62,static_cast<unsigned char>((extension << 4) | 2),
                static_cast<unsigned char>(0x85 | (vvvv << 3)),0x08,static_cast<unsigned char>(opcode),
                static_cast<unsigned char>(modrm)};
            if (modrm == 0x6c) code.insert(code.end(),{0x24,0x80});
            if (modrm == 0xa4) code.insert(code.end(),{0x0c,0x30,0,0,0});
            if (modrm == 0x05) code.insert(code.end(),{0x20,0,0,0});
            evexAccepted(code,source,destination,guardedEnd);
        }
    }
    for (auto opcode : {0x99u,0xa9u,0xb9u}) {
        const std::vector<unsigned char> fma{0x62,0xf2,0xfd,0x08,static_cast<unsigned char>(opcode),0xe5};
        for (unsigned field = 1; field <= 4; ++field) for (unsigned value = 0; value < 256; ++value) {
            auto code = fma; code[field] = static_cast<unsigned char>(value);
            bool accepted = field == 1 ? (value & 15) == 2
                : field == 2 ? (value & 0x87) == 0x85
                : field == 3 ? value == 8
                : value == 0x99 || value == 0xa9 || value == 0xb9;
            if (accepted) evexAccepted(code,source,destination,guardedEnd);
            else evexRejected(code,destination,guardedEnd);
        }
        for (auto prefix : {0x26,0x2e,0x36,0x3e,0x64,0x65,0x66,0x67,0xf0,0xf2,0xf3,
                0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f}) {
            auto code = fma; code.insert(code.begin(),static_cast<unsigned char>(prefix));
            evexRejected(code,destination,guardedEnd);
        }
        std::memcpy(source,fma.data(),fma.size());
        Relocation result;
        require(relocate(distant,MAX_RELOCATED_BYTES,source,fma.size(),result)
            && !std::memcmp(distant,fma.data(),fma.size()),"Nonrelative FMA rejected at distant destination");
        auto rip = fma; rip[5] = 5; rip.insert(rip.end(),{0,0,0,0});
        std::memcpy(source,rip.data(),rip.size());
        require(length(source,rip.size()) == rip.size()
            && !relocate(distant,MAX_RELOCATED_BYTES,source,rip.size(),result),"Far FMA RIP relocation silently truncated");
    }
    const std::vector<unsigned char> valid{0x62,0xf1,0xff,0x08,0x10,0x00};
    for (unsigned field = 1; field <= 4; ++field) for (unsigned value = 0; value < 256; ++value) {
        auto code = valid; code[field] = static_cast<unsigned char>(value);
        bool accepted = field == 1 ? (value & 15) == 1
            : field == 2 ? value == 0xff
            : field == 3 ? value == 8
            : value == 0x10 || value == 0x11 || value == 0x58 || value == 0x59;
        if (accepted) evexAccepted(code,source,destination,guardedEnd);
        else evexRejected(code,destination,guardedEnd);
    }
    for (auto prefix : {0x26,0x2e,0x36,0x3e,0x64,0x65,0x66,0x67,0xf0,0xf2,0xf3,
            0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f}) {
        auto code = valid; code.insert(code.begin(),static_cast<unsigned char>(prefix));
        evexRejected(code,destination,guardedEnd);
    }
    auto overlong = std::vector<unsigned char>(MAX_INSTRUCTION_BYTES,0x66);
    overlong.insert(overlong.end(),valid.begin(),valid.end());
    evexRejected(overlong,destination,guardedEnd);
    for (auto opcode : {0x10,0x11,0x58,0x59,0x99,0xa9,0xb9}) for (bool reverse : {false,true}) {
        auto from = reverse ? destination : source;
        auto to = reverse ? source : destination;
        auto delta = reinterpret_cast<std::intptr_t>(to) - reinterpret_cast<std::intptr_t>(from);
        auto boundary = delta > 0 ? static_cast<std::int64_t>(LONG_MIN) + delta
            : static_cast<std::int64_t>(LONG_MAX) + delta;
        for (auto displacement : {static_cast<std::int64_t>(LONG_MIN),static_cast<std::int64_t>(LONG_MAX),
                boundary,boundary + (delta > 0 ? -1 : 1)}) {
            bool fma = opcode >= 0x99;
            std::vector<unsigned char> code{0x62,static_cast<unsigned char>(fma ? 0xf2 : 0xf1),
                static_cast<unsigned char>(fma ? 0xfd : 0xff),0x08,static_cast<unsigned char>(opcode),0x05,0,0,0,0};
            auto old = static_cast<LONG>(displacement); std::memcpy(code.data() + 6,&old,4);
            checkBoundary(code,code.size(),guardedEnd); std::memcpy(from,code.data(),code.size());
            SetLastError(0x12345);
            require(length(from,code.size()) == code.size() && GetLastError() == 0x12345,
                "EVEX RIP relocation range affected length/error");
            auto adjusted = displacement - delta;
            bool fits = adjusted >= LONG_MIN && adjusted <= LONG_MAX;
            Relocation result{17,19,reinterpret_cast<void*>(1)};
            require(relocate(to,MAX_RELOCATED_BYTES,from,code.size(),result) == fits && GetLastError() == 0x12345,
                "EVEX signed rel32 boundary was not enforced");
            if (fits) require(result.sourceBytes == code.size() && result.destinationBytes == code.size()
                && !result.branchTarget && read<LONG>(to + 6) == adjusted && !std::memcmp(to,code.data(),6),
                "EVEX RIP displacement was not rebased exactly");
            else require(result.sourceBytes == 17 && result.destinationBytes == 19 && result.branchTarget == reinterpret_cast<void*>(1),
                "Rejected EVEX RIP relocation changed result");
            require(!std::memcmp(from,code.data(),code.size()),"EVEX RIP relocation changed source");
            ++evexRangeChecks;
        }
    }
    std::memcpy(source,valid.data(),valid.size());
    Relocation result;
    require(relocate(distant,MAX_RELOCATED_BYTES,source,valid.size(),result)
        && !std::memcmp(distant,valid.data(),valid.size()),"Nonrelative EVEX rejected at distant destination");
    auto rip = valid; rip[5] = 5; rip.insert(rip.end(),{0,0,0,0}); std::memcpy(source,rip.data(),rip.size());
    require(length(source,rip.size()) == rip.size()
        && !relocate(distant,MAX_RELOCATED_BYTES,source,rip.size(),result),"Far EVEX RIP relocation silently truncated");
}
static unsigned rewriteChecks = 0, transactionChecks = 0, unrelocatedChecks = 0, branchRuns = 0, transactionRuns = 0;
static const void* displaced(const unsigned char* end, std::int64_t displacement) {
    return reinterpret_cast<const void*>(reinterpret_cast<std::intptr_t>(end) + displacement);
}
static void unrelocated(const std::vector<unsigned char>& code, unsigned char* source, unsigned char* destination, const char* message) {
    std::memcpy(source, code.data(), code.size());
    std::memset(destination, 0xa5, MAX_RELOCATED_BYTES);
    Relocation result{17, 19, reinterpret_cast<void*>(1), 23, 29};
    SetLastError(0x12345);
    require(!relocate(destination, MAX_RELOCATED_BYTES, source, code.size(), result) && GetLastError() == 0x12345
        && result.sourceBytes == 17 && result.destinationBytes == 19 && result.branchTarget == reinterpret_cast<void*>(1)
        && result.completed == 23 && result.taken == 29, message);
    for (size_t index = 0; index < MAX_RELOCATED_BYTES; ++index) require(destination[index] == 0xa5, message);
    require(!std::memcmp(source, code.data(), code.size()), message);
    ++unrelocatedChecks;
}
// LOOPcc/JRCXZ: the unchanged instruction branches over a short jump to the
// end onto a rel32 jump to the original target.
static void rewritten(const std::vector<unsigned char>& code, unsigned char* source, unsigned char* destination) {
    std::memcpy(source, code.data(), code.size());
    std::memset(destination, 0xa5, MAX_RELOCATED_BYTES);
    Relocation result;
    SetLastError(0x12345);
    require(relocate(destination, MAX_RELOCATED_BYTES, source, code.size(), result) && GetLastError() == 0x12345,
        "LOOP/JRCXZ rewrite rejected or changed LastError");
    auto size = code.size();
    auto target = displaced(source + size, static_cast<std::int8_t>(code.back()));
    require(result.sourceBytes == size && result.destinationBytes == size + 7 && result.completed == size
        && result.taken == size + 2 && result.branchTarget == target, "LOOP/JRCXZ rewrite layout changed");
    require(!std::memcmp(destination, code.data(), size - 1) && destination[size - 1] == 2 && destination[size] == 0xeb
        && destination[size + 1] == 5 && destination[size + 2] == 0xe9
        && displaced(destination + size + 7, read<LONG>(destination + size + 3)) == target,
        "LOOP/JRCXZ rewrite does not reach the original target");
    for (size_t index = size + 7; index < MAX_RELOCATED_BYTES; ++index)
        require(destination[index] == 0xa5, "LOOP/JRCXZ rewrite wrote past its block");
    require(!std::memcmp(source, code.data(), size), "LOOP/JRCXZ rewrite changed source");
    ++rewriteChecks;
}
static void transactional(const std::vector<unsigned char>& code, unsigned char* source, unsigned char* destination, bool fits) {
    std::memcpy(source, code.data(), code.size());
    std::memset(destination, 0xa5, MAX_RELOCATED_BYTES);
    Relocation result{17, 19, reinterpret_cast<void*>(1), 23, 29};
    SetLastError(0x12345);
    auto size = code.size();
    auto target = displaced(source + size, read<LONG>(code.data() + size - 4));
    require(relocate(destination, MAX_RELOCATED_BYTES, source, size, result) == fits && GetLastError() == 0x12345,
        "XBEGIN signed rel32 boundary was not enforced");
    if (fits) {
        require(result.sourceBytes == size && result.destinationBytes == size && result.branchTarget == target
            && result.completed == size && !result.taken, "XBEGIN relocation layout changed");
        require(!std::memcmp(destination, code.data(), size - 4)
            && displaced(destination + size, read<LONG>(destination + size - 4)) == target, "XBEGIN abort target was not rebased exactly");
        for (size_t index = size; index < MAX_RELOCATED_BYTES; ++index)
            require(destination[index] == 0xa5, "XBEGIN relocation wrote past its instruction");
    } else {
        require(result.sourceBytes == 17 && result.destinationBytes == 19 && result.branchTarget == reinterpret_cast<void*>(1)
            && result.completed == 23 && result.taken == 29, "Rejected XBEGIN relocation changed result");
        for (size_t index = 0; index < MAX_RELOCATED_BYTES; ++index)
            require(destination[index] == 0xa5, "Rejected XBEGIN modified staging code");
    }
    require(!std::memcmp(source, code.data(), size), "XBEGIN relocation changed source");
    ++transactionChecks;
}
static void jumpTo(unsigned char* at, const unsigned char* to) {
    at[0] = 0xe9;
    auto relative = static_cast<LONG>(to - (at + 5));
    std::memcpy(at + 1, &relative, sizeof(relative));
}
static void executable(unsigned char* page, bool enable) {
    DWORD old;
    require(VirtualProtect(page, 4096, enable ? PAGE_EXECUTE_READ : PAGE_READWRITE, &old)
        && (!enable || FlushInstructionCache(GetCurrentProcess(), page, 4096)), "Cannot switch execution page protection");
}
// Every LOOPcc/JRCXZ form runs in place and as its relocated block followed by
// the engine's jump back, over counter and ZF states: the path, the counter
// and RFLAGS must agree, and each form must take both paths.
static void branchExecutions() {
    auto page = static_cast<unsigned char*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    require(page != nullptr, "Cannot allocate branch execution page");
    // mov qword [r8+8], taken; mov [r8], rcx; pushfq; pop rax; mov [r8+16], rax; ret; test rdx, rdx
    const unsigned char taken[]{0x49,0xc7,0x40,0x08,1,0,0,0}, fall[]{0x49,0xc7,0x40,0x08,0,0,0,0},
        common[]{0x49,0x89,0x08,0x9c,0x58,0x49,0x89,0x40,0x10,0xc3}, test[]{0x48,0x85,0xd2};
    using Stub = void (*)(std::uint64_t, std::uint64_t, std::uint64_t*);
    for (unsigned char opcode : {0xe0,0xe1,0xe2,0xe3}) for (bool address : {false, true}) for (bool backward : {false, true}) {
        executable(page, false);
        std::memset(page, 0xcc, 4096);
        // 0x00: backward taken path; 0x40: original; 0x80: fall-through path; 0xc0: relocated.
        auto common_ = page + 0x80 + sizeof(fall);
        std::memcpy(page + 0x80, fall, sizeof(fall)); std::memcpy(common_, common, sizeof(common));
        std::memcpy(page, taken, sizeof(taken)); jumpTo(page + sizeof(taken), common_);
        std::memcpy(page + 0x40, test, sizeof(test));
        auto instruction = page + 0x40 + sizeof(test);
        size_t size = address ? 3 : 2;
        instruction[0] = 0x67;
        instruction[size - 2] = opcode;
        jumpTo(instruction + size, page + 0x80);
        auto forward = instruction + size + 5;
        std::memcpy(forward, taken, sizeof(taken)); jumpTo(forward + sizeof(taken), common_);
        auto target = backward ? page : forward;
        instruction[size - 1] = static_cast<unsigned char>(target - (instruction + size));
        std::memcpy(page + 0xc0, test, sizeof(test));
        Relocation result;
        require(relocate(page + 0xc0 + sizeof(test), MAX_RELOCATED_BYTES, instruction, size, result) && result.branchTarget == target,
            "Executed LOOP/JRCXZ rewrite rejected");
        jumpTo(page + 0xc0 + sizeof(test) + result.destinationBytes, instruction + size);
        executable(page, true);
        unsigned paths[2]{};
        for (std::uint64_t counter : {0ull, 1ull, 2ull, 0x80000000ull, 0x100000000ull, 0x100000001ull, ~0ull})
            for (std::uint64_t zero : {0ull, 1ull}) {
                std::uint64_t original[3]{}, relocated[3]{~0ull, ~0ull, ~0ull};
                reinterpret_cast<Stub>(page + 0x40)(counter, zero, original);
                reinterpret_cast<Stub>(page + 0xc0)(counter, zero, relocated);
                require(!std::memcmp(original, relocated, sizeof(original)), "Relocated LOOP/JRCXZ path, counter or flags differ");
                ++paths[original[1]];
                ++branchRuns;
            }
        require(paths[0] && paths[1], "A LOOP/JRCXZ form did not take both paths");
    }
    VirtualFree(page, 0, MEM_RELEASE);
}
static bool restrictedTransactionalMemory() {
    unsigned a, b, c, d;
    return __get_cpuid_count(7, 0, &a, &b, &c, &d) && (b & (1u << 11));
}
static DWORD64 undefinedAt = 0;
LONG CALLBACK undefinedInstruction(EXCEPTION_POINTERS* pointers) {
    if (pointers->ExceptionRecord->ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION) return EXCEPTION_CONTINUE_SEARCH;
    auto& context = *pointers->ContextRecord;
    undefinedAt = context.Rip;
    context.Rip = *reinterpret_cast<DWORD64*>(context.Rsp);
    context.Rsp += 8;
    context.Rax = 0xdead;
    return EXCEPTION_CONTINUE_EXECUTION;
}
// With RTM, an XABORT inside the transaction reaches the original abort target
// from the relocated XBEGIN too; without it, XBEGIN raises #UD in either place.
static void transactionExecutions() {
    auto page = static_cast<unsigned char*>(VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    require(page != nullptr, "Cannot allocate transaction execution page");
    std::memset(page, 0xcc, 4096);
    // xbegin abort; xabort 0x33; mov eax, 1; ret; abort: mov eax, 2; ret
    const unsigned char transaction[]{0xc7,0xf8,9,0,0,0, 0xc6,0xf8,0x33, 0xb8,1,0,0,0, 0xc3, 0xb8,2,0,0,0, 0xc3};
    std::memcpy(page, transaction, sizeof(transaction));
    Relocation result;
    require(relocate(page + 0x40, MAX_RELOCATED_BYTES, page, sizeof(transaction), result) && result.branchTarget == page + 15,
        "Executed XBEGIN relocation rejected");
    jumpTo(page + 0x40 + result.destinationBytes, page + result.sourceBytes);
    executable(page, true);
    using Stub = std::uint64_t (*)();
    auto rtm = restrictedTransactionalMemory();
    auto handler = rtm ? nullptr : AddVectoredExceptionHandler(1, undefinedInstruction);
    require(rtm || handler, "Cannot install #UD observer");
    for (auto entry : {page, page + 0x40}) {
        undefinedAt = 0;
        auto value = reinterpret_cast<Stub>(entry)();
        require(rtm ? value == 2 : value == 0xdead && undefinedAt == reinterpret_cast<DWORD64>(entry),
            "Relocated XBEGIN behaves differently from the original");
        ++transactionRuns;
    }
    if (handler) require(RemoveVectoredExceptionHandler(handler) != 0, "Cannot remove #UD observer");
    VirtualFree(page, 0, MEM_RELEASE);
    std::printf("XBEGIN executions rtm=%u abortTarget=%u undefinedInstruction=%u\n", rtm ? 1u : 0u, rtm ? 2u : 0u, rtm ? 0u : 2u);
}
int main() {
    initialize();
    auto region = static_cast<unsigned char*>(VirtualAlloc(nullptr, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    require(region != nullptr, "Cannot allocate private relocation workspace");
    auto destination = region + 4096;
    SYSTEM_INFO system;
    GetSystemInfo(&system);
    auto page = static_cast<size_t>(system.dwPageSize);
    auto guarded = static_cast<unsigned char*>(VirtualAlloc(nullptr, page * 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    require(guarded != nullptr, "Cannot allocate bounded decoder workspace");
    DWORD previous;
    require(VirtualProtect(guarded + page, page, PAGE_NOACCESS, &previous) != 0, "Cannot protect decoder boundary");
    auto guardedEnd = guarded + page;
    require(!length(guardedEnd, 0), "Zero readable bytes accepted");
    struct Vector { const char* name; std::vector<unsigned char> code; size_t length; };
    for (const auto& vector : {
            Vector{"save RBX in shadow area", {0x48,0x89,0x5c,0x24,0x08}, 5},
            Vector{"push RBP", {0x55}, 1}, Vector{"stack allocation", {0x48,0x83,0xec,0x28}, 4},
            Vector{"ENDBR64", {0xf3,0x0f,0x1e,0xfa}, 4},
            Vector{"VEX vzeroupper", {0xc5,0xf8,0x77}, 3},
            Vector{"VEX vpbroadcastd", {0xc4,0xe2,0x79,0x58,0xc0}, 5},
            Vector{"VEX map3 immediate", {0xc4,0xe3,0x79,0x0f,0xc1,0x03}, 6},
            Vector{"VEX FS memory", {0x64,0xc5,0xf8,0x10,0x00}, 5},
            Vector{"LOCK VEX forbidden", {0xf0,0xc5,0xf8,0x77}, 0},
            Vector{"66 VEX forbidden", {0x66,0xc5,0xf8,0x77}, 0},
            Vector{"F2 VEX forbidden", {0xf2,0xc5,0xf8,0x77}, 0},
            Vector{"F3 VEX forbidden", {0xf3,0xc4,0xe2,0x79,0x58,0xc0}, 0},
            Vector{"REX VEX forbidden", {0x48,0xc5,0xf8,0x77}, 0},
            Vector{"REX then FS VEX forbidden", {0x40,0x64,0xc5,0xf8,0x77}, 0},
            Vector{"reserved VEX MAP0", {0xc4,0xe0,0x78,0x58,0xc0}, 0},
            Vector{"reserved VEX MAP4", {0xc4,0xe4,0x78,0x01,0xc0}, 0},
            Vector{"reserved VEX MAP5", {0xc4,0xe5,0x78,0x58,0xc0}, 0},
            Vector{"EVEX vaddps unsupported", {0x62,0xf1,0x7c,0x48,0x58,0xc0}, 0},
            Vector{"APX REX2 unsupported", {0xd5,0x58,0x01,0xc8}, 0},
            Vector{"APX EVEX addw unsupported", {0x62,0xf4,0x7d,0x18,0x81,0xc1,0x34,0x12}, 0},
            Vector{"prefixed invalid unsupported", {0xf3,0x62,0xf1,0x7c,0x48,0x58,0xc0}, 0}}) {
        checkBoundary(vector.code, vector.length, guardedEnd);
        std::memset(region, 0xcc, 32);
        std::memcpy(region, vector.code.data(), vector.code.size());
        size_t written = 0; void* target = nullptr;
        std::memset(destination, 0xa5, MAX_RELOCATED_BYTES);
        auto size = checkedCopy(destination, region, vector.code.size(), &written, &target);
        if (size != vector.length) { std::fprintf(stderr, "%s: expected %zu, got %zu\n", vector.name, vector.length, size); return 1; }
        require(GetLastError() == 0x12345, "Relocation changed LastError");
        require(std::memcmp(region, vector.code.data(), vector.code.size()) == 0, "Relocation modified source code");
        if (!size) for (size_t index = 0; index < MAX_RELOCATED_BYTES; ++index)
            require(destination[index] == 0xa5, "Rejected encoding modified staging code");
        require(checkedCopy(destination, guardedEnd - vector.code.size(), vector.code.size(), &written, &target)
                == vector.length, "Relocation read past instruction boundary");
        std::printf("%s length=%zu\n", vector.name, size);
    }
    for (const auto& code : {std::vector<unsigned char>{0xe8,0x30,0,0,0},
            {0xe9,0x30,0,0,0}, {0xeb,0x30}, {0x75,0x30}}) {
        std::memcpy(region, code.data(), code.size());
        size_t written = 0; void* target = nullptr;
        require(checkedCopy(destination, region, code.size(), &written, &target) == code.size(), "Relative branch rejected");
        require(target == region + code.size() + 0x30, "Relative branch target changed");
        auto displacement = destination[0] == 0x0f ? 2 : 1;
        require(destination + written + read<LONG>(destination + displacement) == target, "Relocated branch does not reach original target");
    }
    const unsigned char load[] = {0x48,0x8b,0x05,0x20,0,0,0};
    std::memcpy(region, load, sizeof(load));
    size_t written = 0; void* target = nullptr;
    require(checkedCopy(destination, region, sizeof(load), &written, &target) == sizeof(load), "RIP-relative load rejected");
    require(destination + written + read<LONG>(destination + 3) == region + sizeof(load) + 0x20, "RIP-relative address changed");
    require(!checkedCopy(destination, region, sizeof(load) - 1, &written, &target), "Truncated instruction accepted");
    for (auto displacement : {LONG_MIN, LONG_MAX}) {
        for (auto code : {std::vector<unsigned char>{0xe8,0,0,0,0}, {0xe9,0,0,0,0},
                {0x0f,0x85,0,0,0,0}, {0x48,0x8b,0x05,0,0,0,0}}) {
            std::memcpy(code.data() + code.size() - 4, &displacement, sizeof(displacement));
            checkBoundary(code, code.size(), guardedEnd);
            std::memcpy(region, code.data(), code.size());
            require(length(region, code.size()) == code.size(), "rel32 range affected instruction length");
            bool fits = displacement != LONG_MIN;
            require((checkedCopy(destination, region, code.size(), &written, &target) != 0) == fits,
                "rel32 relocation range was not enforced");
            if (fits) require(destination + written + read<LONG>(destination + code.size() - 4)
                    == region + code.size() + displacement, "rel32 maximum relocation target changed");
        }
    }
    std::vector<unsigned char> longest(MAX_INSTRUCTION_BYTES, 0x66);
    longest.back() = 0x90;
    checkBoundary(longest, MAX_INSTRUCTION_BYTES, guardedEnd);
    std::memcpy(region, longest.data(), longest.size());
    require(checkedCopy(guardedEnd - MAX_RELOCATED_BYTES, region, longest.size(), &written, &target) == longest.size(),
        "Maximum-length instruction rejected");
    require(written == MAX_INSTRUCTION_BYTES, "Maximum-length relocation changed size");
    std::vector<unsigned char> overlong(MAX_INSTRUCTION_BYTES + 1, 0x66);
    overlong.back() = 0x90;
    std::memcpy(guardedEnd - overlong.size(), overlong.data(), overlong.size());
    require(!length(guardedEnd - overlong.size(), overlong.size()), "Overlong instruction accepted at page boundary");
    for (auto opcode : {0x75,0xeb}) for (size_t count : {size_t(9),size_t(10),size_t(11)}) {
        std::vector<unsigned char> code(count, 0x2e);
        code.insert(code.end(), {static_cast<unsigned char>(opcode),0x30});
        checkBoundary(code, code.size(), guardedEnd);
        std::memcpy(region, code.data(), code.size());
        auto expanded = count + (opcode == 0x75 ? 6 : 5);
        require((checkedCopy(destination, region, code.size(), &written, &target) != 0)
                == (expanded <= MAX_INSTRUCTION_BYTES), "Widened branch exceeded the instruction length limit");
        if (expanded <= MAX_INSTRUCTION_BYTES) require(written == expanded, "Widened branch size changed");
    }
    std::memset(region, 0x66, 16);
    require(!checkedCopy(destination, region, 16, &written, &target), "Overlong prefix sequence accepted");
    const unsigned char indirect[] = {0xff,0x25,0xf0,0xff,0xff,0x7f};
    std::memcpy(region, indirect, sizeof(indirect));
    require(checkedCopy(destination, region, sizeof(indirect), &written, &target) == sizeof(indirect), "Indirect branch classification dereferenced unreadable target");
    require(target == reinterpret_cast<void*>(~uintptr_t(0)), "Indirect branch should remain dynamic");
    auto distant = static_cast<unsigned char*>(VirtualAlloc(reinterpret_cast<void*>(0x30000000), 65536,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    require(distant != nullptr, "Cannot allocate far relocation workspace");
    std::memcpy(region, load, sizeof(load));
    require(!checkedCopy(distant, region, sizeof(load), &written, &target), "Out-of-range RIP displacement silently truncated");
    const unsigned char shortJump[] = {0xeb,0x30};
    std::memcpy(region, shortJump, sizeof(shortJump));
    require(!checkedCopy(distant, region, sizeof(shortJump), &written, &target), "Out-of-range short branch silently truncated");
    for (auto opcode : {0xe0,0xe1,0xe2,0xe3}) for (auto displacement : {0x80,0x7f,0x00,0xfe}) {
        for (const auto& prefix : {std::vector<unsigned char>{}, {0x67}, {0x48}, {0x2e}, {0x67,0x48}, {0x66}, {0x67,0x66}}) {
            auto code = prefix;
            code.insert(code.end(), {static_cast<unsigned char>(opcode),static_cast<unsigned char>(displacement)});
            checkBoundary(code, code.size(), guardedEnd);
            if (std::find(prefix.begin(), prefix.end(), 0x66) == prefix.end()) rewritten(code, region, destination);
            else unrelocated(code, region, destination, "Operand-size LOOP/JRCXZ relocated");
            unrelocated(code, region, distant, "Out-of-range LOOP/JRCXZ target relocated");
        }
    }
    for (const auto& prefix : {std::vector<unsigned char>{}, {0x2e}, {0x48}, {0x66}, {0x66,0x48}}) {
        bool operand = std::find(prefix.begin(), prefix.end(), 0x66) != prefix.end();
        for (auto displacement : {0x10L, -0x10L, LONG_MIN, LONG_MAX}) {
            auto transaction = prefix;
            transaction.insert(transaction.end(), {0xc7,0xf8});
            auto bytes = static_cast<std::int32_t>(displacement);
            if (operand && prefix.back() == 0x66) transaction.insert(transaction.end(), {0x10,0});
            else transaction.insert(transaction.end(), reinterpret_cast<unsigned char*>(&bytes), reinterpret_cast<unsigned char*>(&bytes) + 4);
            checkBoundary(transaction, transaction.size(), guardedEnd);
            if (operand) unrelocated(transaction, region, destination, "Operand-size XBEGIN relocated");
            else transactional(transaction, region, destination, displacement != LONG_MIN);
            if (displacement == 0x10L || displacement == -0x10L)
                unrelocated(transaction, region, distant, "Out-of-range XBEGIN abort target relocated");
        }
    }
    transactionExecutions();
    branchExecutions();
    const unsigned char move[] = {0xc7,0xc0,0x34,0x12,0,0};
    std::memcpy(region, move, sizeof(move));
    require(checkedCopy(destination, region, sizeof(move), &written, &target) == sizeof(move), "Ordinary C7 MOV was rejected with XBEGIN");
    evex(region,destination,guardedEnd,distant);
    VirtualFree(guarded, 0, MEM_RELEASE);
    VirtualFree(distant, 0, MEM_RELEASE); VirtualFree(region, 0, MEM_RELEASE);
    std::printf("Checked Detours relocation: PASS boundaryChecks=%u evexChecks=%u evexRangeChecks=%u loopRewrites=%u xbeginRelocations=%u rejectedRelocations=%u branchExecutions=%u transactionExecutions=%u vexLegality=1 narrowEvexSd=1 scalarFmaSd=3 unsupportedApx=1 guardPages=1 branchRange=1 wideningLimit=1\n",
        boundaryChecks,evexChecks,evexRangeChecks,rewriteChecks,transactionChecks,unrelocatedChecks,branchRuns,transactionRuns);
}
