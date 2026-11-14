/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <windows.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

// Exercise the Windows unwinder independently of HotSpot. The metadata mode
// transports non-executable method and bytecode addresses between generated
// frames and their physical callers using documented x64 unwind operations.
class DynamicCode {
    unsigned char* _memory = nullptr;
    unsigned char* _code = nullptr;
    bool _gpr = false;
    DWORD _entryCount = 1;
    unsigned char* _low = nullptr;
    void* _lowRegistration = nullptr;
    RUNTIME_FUNCTION _lowFunction{};
    std::array<RUNTIME_FUNCTION,3> _lowFunctions{};
    bool _three = false;
    bool _deep = false;
    bool _lower = false;
    static constexpr DWORD LOW_MARKER = 0x01000000;
    static constexpr DWORD LOW_SIZE = 0x04000000;
    std::array<RUNTIME_FUNCTION, 5> _table{};
    bool _metadata;
    void* _growable = nullptr;
    RUNTIME_FUNCTION _classic{};
    bool _classicRegistered = false;
    static void check(bool value, const char* message) {
        if (!value) { std::fprintf(stderr, "%s (Windows error %lu)\n", message, GetLastError()); std::exit(2); }
    }
public:
    enum class Registration { Fixed, Growable, ShadowClassic, Overlap, GprSave, GprPush, SplitBytes, PoisonFrame, OutsideInfo, ThreeFrames, DeepFrames, LowerBase };
    static constexpr size_t CODE_SIZE = 90;
    explicit DynamicCode(bool metadata, Registration registration = Registration::Fixed) : _metadata(metadata) {
        bool growable = registration != Registration::Fixed;
        bool lower = registration == Registration::LowerBase;
        _lower = lower;
        bool shadow = registration == Registration::ShadowClassic || lower;
        bool replace = registration == Registration::Overlap;
        _gpr = registration == Registration::GprSave || registration == Registration::GprPush || registration == Registration::OutsideInfo;
        _deep = registration == Registration::DeepFrames;
        _three = registration == Registration::ThreeFrames || _deep;
        auto allocationSize = lower ? 131072u : 12288u;
        _memory = static_cast<unsigned char*>(VirtualAlloc(nullptr, allocationSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        check(_memory != nullptr, "Cannot allocate generated code fixture");
        DWORD codeOffset = lower ? 65536u : 0u, infoOffset = 4096;
        _entryCount = metadata ? 4 : 1;
        _code = _memory + codeOffset;
        unsigned char code[CODE_SIZE] = {
            0x55, 0x48,0x89,0xe5, 0x48,0x83,0xec,0x40, // push rbp; mov rbp,rsp; sub rsp,64
            0x48,0xb8, 0,0,0,0,0,0,0,0,              // mov rax,metadata-address
            0x48,0x89,0x45,0xe8,                       // mov [rbp-24],rax
            0x48,0x8d,0x45,0x10, 0x48,0x89,0x45,0xf8, // save caller SP at [rbp-8]
            0xb9,0,0,0,4,                              // mov ecx,0x04000000
            0x48,0x69,0xc0,0x6d,0x4e,0xc6,0x41,       // imul rax,rax,0x41c64e6d
            0x48,0xc1,0xc0,0x0d, 0xff,0xc9, 0x75,0xf1, // rol rax,13; dec ecx; jnz loop
            0x48,0x83,0xc4,0x40, 0x5d, 0xc3           // add rsp,64; pop rbp; ret
        };
        auto marker = reinterpret_cast<std::uintptr_t>(_memory + 8192);
        if (metadata) {
            _low = static_cast<unsigned char*>(VirtualAlloc(reinterpret_cast<void*>(0x30000000),LOW_SIZE,MEM_RESERVE | MEM_COMMIT,PAGE_READWRITE));
            check(_low != nullptr,"Cannot reserve low metadata probe");
            marker = reinterpret_cast<std::uintptr_t>(_low + LOW_MARKER);
        }
        std::memcpy(code + 10, &marker, sizeof(marker));
        if (_three) {
            std::memmove(code + 44,code + 30,26);
            unsigned char extra[] = {0x48,0xb8,0,0,0,0,0,0,0,0,0x48,0x89,0x45,0xc0};
            auto bcp = marker + 4096;
            std::memcpy(extra + 2,&bcp,sizeof(bcp));
            std::memcpy(code + 30,extra,sizeof(extra));
        }
        if (_deep) {
            unsigned char recursion[] = {
                0x85,0xc9,0x74,0x10,0xff,0xc9,0x48,0xb8,0,0,0,0,0,0,0,0,
                0xff,0xd0,0xeb,0x14,0xb9,0,0,0,4,
                0x48,0x69,0xc0,0x6d,0x4e,0xc6,0x41,0x48,0xc1,0xc0,0x0d,0xff,0xc9,0x75,0xf1,
                0x48,0x83,0xc4,0x40,0x5d,0xc3
            };
            auto entry = reinterpret_cast<std::uintptr_t>(_code);
            std::memcpy(recursion + 8,&entry,sizeof(entry));
            std::memcpy(code + 44,recursion,sizeof(recursion));
        }
        if (_gpr) {
            const unsigned char clobber[] = {0x48,0xf7,0xd5,0x48,0x0f,0xaf,0xc0}; // not rbp; imul rax,rax
            std::memcpy(code + 35, clobber, sizeof(clobber));
        }
        if (registration == Registration::SplitBytes) {
            const unsigned char split[] = {0x48,0x03,0xc3,0x48,0xc1,0xc0,0x0d,0xff,0xc9,0x75,0xf5,0x90,0x90,0x90,0x90};
            std::memcpy(code + 35,split,sizeof(split));
        }
        if (registration == Registration::PoisonFrame) {
            const unsigned char poison[] = {0x31,0xc0,0x48,0x89,0x45,0x20,0x48,0x0f,0xaf,0xc0,0x90,0x90};
            std::memcpy(code + 30,poison,sizeof(poison));
            code[49] = 0xf2;
        }
        std::memcpy(_code, code, sizeof(code));
        // Normal prologue: ALLOC_SMALL(64), SET_FPREG(rbp), PUSH_NONVOL(rbp).
        const unsigned char normal[] = {1,8,3,5, 8,0x72, 4,3, 1,0x50, 0,0};
        std::memcpy(_memory + infoOffset, normal, sizeof(normal));
        if (lower) std::memcpy(_code + 4096,normal,sizeof(normal));
        if (!metadata) _table[0] = {codeOffset, codeOffset + static_cast<DWORD>(CODE_SIZE), infoOffset};
        else {
            // Emit [rbp-24], then continue through the saved frame pointer and
            // return address. Metadata addresses are deliberately not executable.
            const unsigned char first[] = {2,0,2,0x25, 0,3, 0,2};
            // Restore the independent interpreter sender SP after obtaining the
            // return PC. The frame base remains stable across the RBP restores.
            unsigned char second[] = {
                1,0,9,0x15, 0,3, 0,0x22, 0,0x0a, 0,0x54,1,0,
                0,3, 0,0x12, 0,0x54,2,0, 0,0
            };
            const unsigned char chain[] = {0x21,0,0,5};
            second[0] = 2; _memory[8192] = 0xc3;
            _low[LOW_MARKER] = 0xc3;
            if (_three) _low[LOW_MARKER + 4096] = 0xc3;
            std::memcpy(_low + 4096,second,sizeof(second));
            const unsigned char bcp[] = {2,0,1,0x45,0,3,0,0};
            if (_three) std::memcpy(_low + 4160,bcp,sizeof(bcp));
            std::memcpy(_memory + infoOffset + 32, first, sizeof(first));
            std::memcpy(_memory + infoOffset + 64, second, sizeof(second));
            std::memcpy(_memory + infoOffset + 96, chain, sizeof(chain));
            RUNTIME_FUNCTION parent{codeOffset, codeOffset + static_cast<DWORD>(CODE_SIZE), infoOffset};
            std::memcpy(_memory + infoOffset + 100, &parent, sizeof(parent));
            _table = {{{codeOffset,codeOffset + 35,infoOffset}, {codeOffset + 35,codeOffset + 50,infoOffset + 32},
                {codeOffset + 50,codeOffset + static_cast<DWORD>(CODE_SIZE),infoOffset + 96}, {8192,8193,infoOffset + 64}}};
            if (_three) {
                _table[0].EndAddress += 14;
                _table[1].BeginAddress += 14; _table[1].EndAddress += 14;
                _table[2].BeginAddress += 14;
            }
            if (_deep) {
                _table[0].EndAddress = 44;
                _table[1].BeginAddress = 44; _table[1].EndAddress = 84;
                _table[2].BeginAddress = 84;
            }
            if (lower) _entryCount = 3;
        }
        if (_gpr) {
            const unsigned char save[] = {1,0,3,0, 0,0x54,8,0, 0,0x82,0,0};
            const unsigned char push[] = {1,0,2,0, 0,0x72,0,0x50};
            const unsigned char chain[] = {0x21,0,0,5};
            std::memcpy(_memory + 4224, registration == Registration::GprSave ? save : push,
                registration == Registration::GprSave ? sizeof(save) : sizeof(push));
            std::memcpy(_memory + 4192, chain, sizeof(chain));
            RUNTIME_FUNCTION parent{0,static_cast<DWORD>(CODE_SIZE),4096};
            std::memcpy(_memory + 4196,&parent,sizeof(parent));
            _table = {{{0,35,4096},{35,50,4224},{50,static_cast<DWORD>(CODE_SIZE),4192},{}}};
            _entryCount = 3;
        }
        if (registration == Registration::SplitBytes) {
            const unsigned char body[] = {1,0,2,0,0,0x72,0,0x50};
            const unsigned char leaf[] = {1,0,0,0};
            const unsigned char chain[] = {0x21,0,0,5};
            std::memcpy(_memory + 4224,body,sizeof(body)); std::memcpy(_memory + 4256,leaf,sizeof(leaf));
            std::memcpy(_memory + 4192,chain,sizeof(chain));
            RUNTIME_FUNCTION parent{0,static_cast<DWORD>(CODE_SIZE),4096}; std::memcpy(_memory + 4196,&parent,sizeof(parent));
            _table = {{{0,35,4096},{35,37,4224},{37,38,4256},{38,50,4224},{50,static_cast<DWORD>(CODE_SIZE),4192}}};
            _entryCount = 5;
        }
        DWORD previous;
        check(VirtualProtect(_code, 4096, PAGE_EXECUTE_READ, &previous) != FALSE, "Cannot protect generated code");
        check(FlushInstructionCache(GetCurrentProcess(), _code, CODE_SIZE) != FALSE, "Cannot flush generated code");
        if (growable) {
            using Add = DWORD (NTAPI*)(void**, PRUNTIME_FUNCTION, DWORD, DWORD, ULONG_PTR, ULONG_PTR);
            auto add = reinterpret_cast<Add>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlAddGrowableFunctionTable"));
            check(add != nullptr, "Growable function tables are unavailable");
            if (_low) {
                _lowFunction = {0,LOW_SIZE,4096};
                _lowFunctions = {{{0,LOW_MARKER,4096},{LOW_MARKER,LOW_MARKER + 1,4160},{LOW_MARKER + 1,LOW_SIZE,4096}}};
                check(add(&_lowRegistration,_three ? _lowFunctions.data() : &_lowFunction,_three ? 3 : 1,_three ? 3 : 1,
                    reinterpret_cast<ULONG_PTR>(_low),reinterpret_cast<ULONG_PTR>(_low + LOW_SIZE)) == 0,"Cannot register low metadata probe");
            }
            auto base = reinterpret_cast<ULONG_PTR>(_memory);
            _classic = {0, static_cast<DWORD>(CODE_SIZE), 4096};
            if (shadow) {
                check(RtlAddFunctionTable(&_classic, 1, base + codeOffset) != FALSE, "Cannot register the original function table");
                _classicRegistered = true;
            }
            void* previousTable = nullptr;
            if (replace) check(add(&previousTable, &_classic, 1, 1, base, base + 12288) == 0, "Cannot register previous growable table");
            auto status = add(&_growable, _table.data(), _entryCount, static_cast<DWORD>(_table.size()), base,
                base + (registration == Registration::OutsideInfo ? CODE_SIZE : allocationSize));
            std::printf("DYNAMIC_REGISTRATION status=%08lx shadow=%u replace=%u\n", status, shadow ? 1u : 0u, replace ? 1u : 0u);
            if (replace) {
                check(status == 0xc0000018, "Overlapping growable tables were not rejected as expected");
                _growable = previousTable; previousTable = nullptr;
                _metadata = false;
                status = 0;
                std::puts("DYNAMIC_OVERLAP_REJECTED original-table-retained");
            }
            check(status == 0, "Cannot register growable unwind table");
            if (previousTable) {
                using Delete = void (NTAPI*)(void*);
                reinterpret_cast<Delete>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlDeleteGrowableFunctionTable"))(previousTable);
            }
        } else check(RtlAddFunctionTable(_table.data(), _entryCount, reinterpret_cast<DWORD64>(_memory)) != FALSE, "Cannot register generated unwind table");
        verify();
        std::printf("DYNAMIC_CODE begin=%p size=%zu marker=%p metadata=%u\n", _code, CODE_SIZE, _low ? _low + LOW_MARKER : _memory + 8192, _metadata ? 1u : 0u);
    }
    DynamicCode(const DynamicCode&) = delete;
    DynamicCode& operator=(const DynamicCode&) = delete;
    ~DynamicCode() {
        if (_growable) {
            using Delete = void (NTAPI*)(void*);
            auto remove = reinterpret_cast<Delete>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlDeleteGrowableFunctionTable"));
            check(remove != nullptr, "Cannot find growable table cleanup");
            remove(_growable);
        } else check(RtlDeleteFunctionTable(_table.data()) != FALSE, "Cannot retire generated unwind table");
        if (_classicRegistered) check(RtlDeleteFunctionTable(&_classic) != FALSE, "Cannot retire the original function table");
        if (_lowRegistration) {
            using Delete = void (NTAPI*)(void*);
            reinterpret_cast<Delete>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"RtlDeleteGrowableFunctionTable"))(_lowRegistration);
        }
        if (_low) VirtualFree(_low,0,MEM_RELEASE);
        VirtualFree(_memory, 0, MEM_RELEASE);
    }
    void verify() const {
        std::uint64_t stack[32]{};
        auto fp = reinterpret_cast<DWORD64>(&stack[24]);
        stack[21] = reinterpret_cast<DWORD64>(_low ? _low + LOW_MARKER : _memory + 8192);
        if (_three) stack[16] = stack[21] + 4096;
        stack[23] = fp + 40;
        stack[24] = 0x12345678;
        stack[25] = 0x24681357;
        CONTEXT context{};
        context.Rip = reinterpret_cast<DWORD64>(_code + (_deep ? 76 : _three ? 56 : 42));
        context.Rsp = fp - 64; context.Rbp = fp;
        if (_gpr) context.Rbp = 0;
        DWORD64 initialBase;
        auto initial = RtlLookupFunctionEntry(context.Rip, &initialBase, nullptr);
        if (_classicRegistered) check((initial == &_classic) != _lower,"Unexpected classic/growable lookup precedence");
        if (_lower) std::puts("DYNAMIC_LOWER_ORIGIN selects-growable original-classic-retained");
        bool metadata = _metadata && initial != &_classic;
        std::printf("DYNAMIC_USER_TABLE original=%u\n", initial == &_classic ? 1u : 0u);
        for (int i = 0; i < (metadata ? (_three ? 3 : 2) : 1); ++i) {
            DWORD64 base, establisher;
            void* handler;
            auto entry = RtlLookupFunctionEntry(context.Rip, &base, nullptr);
            check(entry != nullptr, "Generated function entry is unavailable");
            RtlVirtualUnwind(UNW_FLAG_NHANDLER, base, context.Rip, entry, &context, &handler, &establisher, nullptr);
            if (metadata && i == 0) check(context.Rip == stack[21] && context.Rbp == fp, "Metadata frame was not emitted");
            if (_three && i == 1) check(context.Rip == stack[16] && context.Rbp == fp,"Bytecode frame was not emitted");
        }
        if (context.Rip != stack[25] || context.Rsp != (metadata ? stack[23] : fp + 16) || context.Rbp != stack[24]) {
            std::printf("DYNAMIC_CONTEXT rip=%llx rsp-delta=%lld rbp=%llx expected-rsp-delta=%lld\n", context.Rip,
                static_cast<long long>(context.Rsp - fp), context.Rbp, static_cast<long long>((metadata ? stack[23] : fp + 16) - fp));
            check(false, "Generated physical caller was not restored");
        }
    }
    std::uint64_t run() const { return reinterpret_cast<std::uint64_t(*)(unsigned)>(_code)(_deep ? 10 : 0x04000000); }
};
