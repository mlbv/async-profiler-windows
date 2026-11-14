/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsNativeProbeTarget.h"
#include <cstdio>
#include <cstdlib>

using namespace WindowsProfiler::NativeProbe;
static void require(bool value, const char* message) {
    if (!value) { std::fprintf(stderr, "%s\n", message); std::exit(1); }
}
int main() {
    struct HardwareCase { const char* input; bool memory; const char* target; unsigned access, width, argument; };
    for (const auto& test : {
            HardwareCase{"function", false, "function", 0, 1, 0},
            {"ucrtbase.dll!malloc+0x10", false, "ucrtbase.dll!malloc+0x10", 0, 1, 1},
            {"ucrtbase.dll!malloc{3}", false, "ucrtbase.dll!malloc", 0, 1, 3},
            {"Namespace::function", false, "Namespace::function", 0, 1, 0},
            {"mem:0x1000:8:rw", true, "0x1000", 3, 8, 0},
            {"mem:4096/4:w", true, "0x1000", 1, 4, 0},
            {"mem:0x1000/8:x", true, "0x1000", 0, 1, 0},
            {"mem:0x1000:4", true, "0x1000", 3, 4, 0},
            {"read", false, "read", 0, 1, 3}}) {
        HardwareSpec result;
        require(!parseHardware(test.input, test.memory, result), "Legacy hardware probe was rejected");
        require(result.target == test.target && result.access == test.access && result.length == test.width
            && result.counterArg == test.argument, "Hardware parser behavior changed");
    }
    HardwareSpec hardware;
    require(!parseHardware("kept", false, hardware), "Hardware baseline parse failed");
    for (const auto* text : {"", "fn{0}", "fn{5}", "fn{1}tail", "0", "123x", "fn:r", "fn/9", "fn/nope"}) {
        require(parseHardware(text, false, hardware), "Invalid hardware selector accepted");
        require(hardware.target == "kept", "Failed hardware parse mutated previous result");
    }
    require(parseHardware("mem", true, hardware), "Truncated memory prefix accepted");
    SoftwareSpec software;
    require(!parseSoftware("uprobe:C:\\Program Files\\燃烧𠮷.dll+0x400", software), "Windows software pathname rejected");
    require(software.target == "C:\\Program Files\\燃烧𠮷.dll" && software.offset == 1024
        && software.mode == Mode::Entry && software.kind == TargetKind::FileOffset, "PE file offset changed into an address or access mode");
    require(!parseSoftware("uretprobe:fixture.dll+066", software) && software.offset == 54 && software.mode == Mode::Return,
        "Upstream octal return-probe offset changed");
    require(!parseSoftware("uprobe:fixture.dll!function+-10", software) && software.offset == -10
        && software.kind == TargetKind::Symbol, "Explicit symbol-relative offset rejected");
    require(!parseSoftware("uprobe:ucrtbase.dll!malloc{1}", software) && software.target == "ucrtbase.dll!malloc{1}",
        "Hardware argument-counter grammar leaked into software target parsing");
    require(!parseSoftware("uprobe:fixture.dll!Class::operator+", software)
        && software.target == "fixture.dll!Class::operator+" && software.offset == 0, "C++ operator name was parsed as an offset");
    require(!parseSoftware("uprobe:fixture.dll+123", software), "Software baseline parse failed");
    for (const auto* text : {"uprobe:", "uretprobe:", "uprobe:fixture.dll+", "uprobe:fixture.dll+0xGG",
            "uprobe:fixture.dll+-1", "uprobe:fixture.dll+9223372036854775808", "uprobe:!symbol", "uprobe:module!", "kprobe:symbol"}) {
        require(parseSoftware(text, software), "Invalid software selector accepted");
        require(software.target == "fixture.dll" && software.offset == 123, "Failed software parse mutated previous result");
    }
    std::puts("Native hardware/software target parser: PASS");
}
