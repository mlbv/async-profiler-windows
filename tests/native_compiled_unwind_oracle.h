/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "windowsCompiledUnwind.h"
#include <windows.h>
#include <cassert>
#include <cstring>

static void unwindInfo(unsigned char* info,
        const WindowsProfiler::JavaUnwind::Compiled::Span& span) {
    assert(span.proven && span.returnOffset <= 128);
    std::memset(info,0,16);
    info[0] = 2;
    if (span.fpOffset >= 0) {
        assert(span.fpOffset + 8 == span.returnOffset);
        if (span.fpOffset) { info[2] = 2; info[5] = static_cast<unsigned char>(((span.fpOffset / 8 - 1) << 4) | 2); info[7] = 0x50; }
        else { info[2] = 1; info[5] = 0x50; }
    } else if (span.returnOffset) { info[2] = 1; info[5] = static_cast<unsigned char>(((span.returnOffset / 8 - 1) << 4) | 2); }
}

static unsigned contexts(const std::vector<unsigned char>& code,
        const std::vector<WindowsProfiler::JavaUnwind::Compiled::Span>& spans) {
    auto page = static_cast<unsigned char*>(VirtualAlloc(nullptr,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    assert(page && code.size() <= 4096);
    std::memcpy(page,code.data(),code.size());
    unsigned checked = 0;
    constexpr DWORD64 originalRbp = 0x1122334455667788, callerIp = 0x12345678, poison = 0xbad0bad0bad0bad0;
    for (const auto& span : spans) if (span.proven) {
        auto info = page + 4096;
        unwindInfo(info,span);
        RUNTIME_FUNCTION function{span.begin,span.end,4096};
        for (auto offset = span.begin; offset < span.end; ++offset) {
            DWORD64 stack[512];
            for (auto& value : stack) value = poison;
            auto returnAddress = stack + 256;
            *returnAddress = callerIp;
            CONTEXT context{};
            context.Rip = reinterpret_cast<DWORD64>(page + offset);
            context.Rsp = reinterpret_cast<DWORD64>(returnAddress) - span.returnOffset;
            context.Rbp = span.fpOffset >= 0 ? poison : originalRbp;
            if (span.fpOffset >= 0) *reinterpret_cast<DWORD64*>(context.Rsp + span.fpOffset) = originalRbp;
            void* handler;
            DWORD64 establisher;
            RtlVirtualUnwind(UNW_FLAG_NHANDLER,reinterpret_cast<DWORD64>(page),context.Rip,&function,&context,&handler,&establisher,nullptr);
            assert(context.Rip == callerIp);
            assert(context.Rsp == reinterpret_cast<DWORD64>(returnAddress + 1));
            assert(context.Rbp == originalRbp);
            ++checked;
        }
    }
    VirtualFree(page,0,MEM_RELEASE);
    return checked;
}
