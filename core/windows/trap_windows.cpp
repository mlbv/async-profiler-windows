/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "trap.h"
#include "windowsBreakpoints.h"
#include "allocTracer.h"
#include "profiler.h"
#include "log.h"
#include "os.h"

uintptr_t Trap::_page_start[TRAP_COUNT]{};

void Trap::assign(const void* address, uintptr_t offset) {
    release();
    _entry = address == nullptr ? 0 : reinterpret_cast<uintptr_t>(address) + offset;
    _page_start[_id] = _entry & ~OS::page_mask;
}
void Trap::pair(Trap&) {}
bool Trap::isFaultInstruction(uintptr_t) { return false; }

bool Trap::prepare() {
    if (!_entry || _prepared) return true;
    auto error = WindowsProfiler::Breakpoints::start(_id, reinterpret_cast<void*>(_entry), onBreakpoint, this);
    if (error) { Log::error("%s", error.message()); return false; }
    _prepared = true;
    return true;
}
void Trap::release() {
    _armed.store(false, std::memory_order_release);
    if (_prepared) {
        WindowsProfiler::Breakpoints::stop(_id);
        _prepared = false;
    }
    _armed.store(false, std::memory_order_release);
}
bool Trap::install() {
    if (!_entry) return true;
    if (!_prepared) return false;
    _armed.store(true, std::memory_order_release);
    return true;
}
bool Trap::uninstall() { _armed.store(false, std::memory_order_release); return true; }

void Trap::onBreakpoint(CONTEXT& context, void* parameter) {
    auto& trap = *static_cast<Trap*>(parameter);
    if (trap._id >= 2) {
        if (!trap._armed.exchange(false, std::memory_order_acq_rel)) return;
    } else if (!trap._armed.load(std::memory_order_acquire)) return;
    siginfo_t info{};
    info.si_signo = SIGTRAP;
    if (trap._id >= 2) Profiler::instance()->trapHandler(SIGTRAP, &info, &context);
    else AllocTracer::trapHandler(SIGTRAP, &info, &context);
}
