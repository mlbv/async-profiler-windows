/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsNativeProbeTarget.h"
#include <cerrno>
#include <cstdlib>
#include <cstdio>
#include <utility>

namespace WindowsProfiler::NativeProbe {
namespace {
size_t accessSeparator(const std::string& text) {
    auto colon = text.rfind(':');
    return colon != std::string::npos && (colon == 0 || text[colon - 1] != ':') ? colon : std::string::npos;
}
unsigned knownCounter(const std::string& symbol) {
    auto begin = symbol.rfind('!');
    auto name = symbol.substr(begin == std::string::npos ? 0 : begin + 1);
    if (auto plus = name.rfind('+'); plus != std::string::npos) name.resize(plus);
    if (name == "malloc") return 1;
    if (name == "mmap" || name == "munmap") return 2;
    if (name == "read" || name == "write" || name == "send" || name == "recv" || name == "sendto" || name == "recvfrom") return 3;
    return 0;
}
}

const char* parseHardware(std::string_view event, bool memory, HardwareSpec& result) {
    if (event.find('\0') != std::string_view::npos) return "Native probe target must not contain NUL";
    if (memory && !event.starts_with("mem:")) return "A memory watchpoint requires mem:";
    HardwareSpec parsed;
    std::string text(event.substr(memory ? 4 : 0));
    if (auto brace = text.find_first_of("{}"); brace != std::string::npos) {
        if (text[brace] != '{' || text.size() != brace + 3 || text.back() != '}'
                || text[brace + 1] < '1' || text[brace + 1] > '4') return "Only arguments 1-4 can be counted, using {1} through {4}";
        parsed.counterArg = static_cast<unsigned>(text[brace + 1] - '0'); text.resize(brace);
    }
    parsed.access = memory ? 3 : 0;
    if (auto colon = accessSeparator(text); colon != std::string::npos) {
        auto mode = text.substr(colon + 1);
        if (mode == "w") parsed.access = 1;
        else if (mode == "rw" || mode == "wr") parsed.access = 3;
        else if (mode == "x") parsed.access = 0;
        else if (mode.empty() || mode[0] < '0' || mode[0] > '9') return "x64 memory breakpoints support w, rw, or x; read-only mode is unavailable";
        else colon = std::string::npos;
        if (colon != std::string::npos) text.resize(colon);
    }
    auto slash = text.rfind('/'), colon = accessSeparator(text);
    auto width = slash != std::string::npos ? slash : colon;
    if (width != std::string::npos) {
        auto value = text.c_str() + width + 1;
        char* end;
        errno = 0;
        auto length = std::strtoul(value, &end, 0);
        if (end == value || *end || errno == ERANGE || length > 8) return "Invalid data watchpoint length";
        parsed.length = static_cast<unsigned>(length); text.resize(width);
        if (parsed.access == 0 && slash != std::string::npos && parsed.length == sizeof(uintptr_t)) parsed.length = 1;
    }
    if (text.empty()) return "Native probe target must not be empty";
    if (!parsed.counterArg && parsed.access == 0) parsed.counterArg = knownCounter(text);
    if (text[0] >= '0' && text[0] <= '9' && !text.starts_with("0x")) {
        char* end;
        errno = 0;
        auto address = std::strtoull(text.c_str(), &end, 0);
        if (end == text.c_str() || (*end && *end != '+') || errno == ERANGE || address == 0) return "Invalid data watchpoint address";
        char hex[2 + 2 * sizeof(uintptr_t) + 1];
        std::snprintf(hex, sizeof(hex), "0x%llx", address);
        text = std::string(hex) + end;
    }
    parsed.target = std::move(text); result = std::move(parsed);
    return nullptr;
}

const char* parseSoftware(std::string_view event, SoftwareSpec& result) {
    if (event.find('\0') != std::string_view::npos) return "Software probe target must not contain NUL";
    SoftwareSpec parsed;
    if (event.starts_with("uprobe:")) event.remove_prefix(7);
    else if (event.starts_with("uretprobe:")) { parsed.mode = Mode::Return; event.remove_prefix(10); }
    else return "Software probes require uprobe: or uretprobe:";
    if (event.empty()) return "Software probe target must not be empty";
    std::string text(event);
    parsed.kind = text.find('!') == std::string::npos ? TargetKind::FileOffset : TargetKind::Symbol;
    if (auto plus = text.rfind('+'); plus != std::string::npos) {
        auto suffix = text.c_str() + plus + 1;
        bool numeric = *suffix == '-' || *suffix == '+' || (*suffix >= '0' && *suffix <= '9');
        if (parsed.kind == TargetKind::FileOffset || numeric) {
            char* end;
            errno = 0;
            auto offset = std::strtoll(suffix, &end, 0);
            if (end == suffix || *end || errno == ERANGE) return "Invalid software probe offset";
            parsed.offset = offset; text.resize(plus);
        }
    }
    if (text.empty()) return "Software probe target must not be empty";
    if (parsed.kind == TargetKind::FileOffset && parsed.offset < 0) return "A PE file offset must not be negative";
    if (parsed.kind == TargetKind::Symbol && (text.front() == '!' || text.back() == '!')) return "Software symbols require module!symbol";
    parsed.target = std::move(text); result = std::move(parsed);
    return nullptr;
}
}
