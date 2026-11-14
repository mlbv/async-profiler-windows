/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsCfiHistory.h"
#include <cassert>
#include <cstdio>

using WindowsProfiler::JavaUnwind::Certainty;
using WindowsProfiler::JavaUnwind::CfiHistory;

int main() {
    CfiHistory history;
    auto code = history.addArea(0x100000,0x200000,false);
    auto first = history.addFunction(code,0x101000,0x101100,{{0,0x20,true},{0x20,0x60,false},{0x60,0x100,true}});
    assert(history.certainty(0x101010,90) == Certainty::Unproven);
    history.publish(code,100); history.activate(first,100);
    assert(history.certainty(0x101010,99) == Certainty::Unproven);
    assert(history.certainty(0x101010,100) == Certainty::Proven);
    assert(history.certainty(0x101030,120) == Certainty::Unproven);
    assert(history.certainty(0x103000,120) == Certainty::Unproven);
    assert(history.certainty(0x900000,120) == Certainty::NotManaged);
    assert(history.certainty(0x900000,120,true) == Certainty::Unproven);
    history.unpublish(code,150);
    assert(history.certainty(0x101010,149) == Certainty::Proven);
    assert(history.certainty(0x101010,150) == Certainty::Unproven);
    history.publish(code,170);
    assert(history.certainty(0x101010,169) == Certainty::Unproven);
    assert(history.certainty(0x101010,170) == Certainty::Proven);
    history.retire(first,180); history.unpublish(code,180);
    auto reused = history.addFunction(code,0x101000,0x101100,{{0,0x20,false},{0x20,0x100,true}});
    history.publish(code,200); history.activate(reused,200);
    assert(history.certainty(0x101010,120) == Certainty::Proven);
    assert(history.certainty(0x101030,120) == Certainty::Unproven);
    assert(history.certainty(0x101010,190) == Certainty::Unproven);
    assert(history.certainty(0x101010,210) == Certainty::Unproven);
    assert(history.certainty(0x101030,210) == Certainty::Proven);
    auto overlap = history.addFunction(code,0x101040,0x101080,{{0,0x40,true}});
    history.activate(overlap,205);
    assert(history.certainty(0x101050,210) == Certainty::Unproven);
    auto pages = history.addFunction(code,0x101ff0,0x102020,{{0,0x30,true}});
    history.activate(pages,205);
    assert(history.certainty(0x102010,210) == Certainty::Proven);
    auto metadata = history.addArea(0x300000,0x400000,true);
    history.publish(metadata,110);
    assert(history.certainty(0x310000,120,false,true) == Certainty::Proven);
    assert(history.certainty(0x310000,120,false,false) == Certainty::Unproven);
    history.unpublish(metadata,130);
    assert(history.certainty(0x310000,140,false,true) == Certainty::Unproven);
    assert(history.certainty(0x310000,120,false,true) == Certainty::Proven);
    history.clear();
    assert(history.certainty(0x101010,120) == Certainty::NotManaged);
    assert(history.certainty(0x101010,120,true) == Certainty::Unproven);
    std::puts("CFI_HISTORY_OK publication-gaps address-reuse ambiguity metadata cross-page");
}
