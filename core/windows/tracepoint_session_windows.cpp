/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsTracepointSession.h"
#include <evntprov.h>
#include <cstddef>
#include <cstdint>

namespace WindowsProfiler::Tracepoint {
namespace {
constexpr ULONG stackTraceProperty = 0x00000004;
constexpr ULONG pidFilterType = 0x80000004;
constexpr ULONG eventIdFilterType = 0x80000200;
struct EventIdFilter { BOOLEAN include; UCHAR reserved; USHORT count; USHORT ids[3]; };
bool kernelSelected(const ProviderLease& lease) { return IsEqualGUID(lease.selected.provider, KERNEL_PROCESS_PROVIDER); }
ULONG enablePrimary(ProviderLease& lease) {
    bool kernel = kernelSelected(lease);
    EventIdFilter ids{TRUE, 0, 1, {lease.selected.eventId, 0, 0}};
    if (kernel) {
        ids.ids[0] = 3; ids.ids[1] = 4; ids.count = 2;
        if (lease.selected.eventId != 3 && lease.selected.eventId != 4) ids.ids[ids.count++] = lease.selected.eventId;
    }
    EVENT_FILTER_DESCRIPTOR filters[2]{};
    filters[0].Ptr = reinterpret_cast<ULONGLONG>(&lease.pid); filters[0].Size = sizeof(lease.pid); filters[0].Type = pidFilterType;
    filters[1].Ptr = reinterpret_cast<ULONGLONG>(&ids); filters[1].Size = offsetof(EventIdFilter, ids) + ids.count * sizeof(USHORT);
    filters[1].Type = eventIdFilterType;
    ENABLE_TRACE_PARAMETERS parameters{};
    parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    parameters.EnableProperty = lease.selected.stacks ? stackTraceProperty : 0;
    parameters.SourceId = lease.source;
    parameters.EnableFilterDesc = kernel ? filters + 1 : filters;
    parameters.FilterDescCount = lease.selected.named ? (kernel ? 0 : 1) : (kernel ? 1 : 2);
    if (!parameters.FilterDescCount) parameters.EnableFilterDesc = nullptr;
    return EnableTraceEx2(lease.session, &lease.selected.provider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        0xff, UINT64_MAX, 0, 5000, &parameters);
}
}

ULONG enableLifecycle(ProviderLease& lease) {
    if (!lease.session || !lease.pid) return ERROR_INVALID_PARAMETER;
    if (lease.lifecycleEnabled || lease.primaryEnabled) return ERROR_ALREADY_INITIALIZED;
    lease.lifecycleEnabled = true;
    return kernelSelected(lease) ? enablePrimary(lease) : EnableTraceEx2(lease.session, &KERNEL_PROCESS_PROVIDER,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER, 0xff, 0x20, 0, 5000, nullptr);
}
ULONG enableSelected(ProviderLease& lease) {
    if (!lease.lifecycleEnabled) return ERROR_INVALID_STATE;
    if (kernelSelected(lease)) return ERROR_SUCCESS;
    if (lease.primaryEnabled) return ERROR_ALREADY_INITIALIZED;
    lease.primaryEnabled = true;
    return enablePrimary(lease);
}
ULONG disableProviders(ProviderLease& lease) {
    ULONG failure = ERROR_SUCCESS;
    if (lease.primaryEnabled) {
        lease.primaryEnabled = false;
        failure = EnableTraceEx2(lease.session, &lease.selected.provider, EVENT_CONTROL_CODE_DISABLE_PROVIDER,
            0, 0, 0, 5000, nullptr);
    }
    if (lease.lifecycleEnabled) {
        lease.lifecycleEnabled = false;
        auto result = EnableTraceEx2(lease.session, &KERNEL_PROCESS_PROVIDER, EVENT_CONTROL_CODE_DISABLE_PROVIDER,
            0, 0, 0, 5000, nullptr);
        if (!failure) failure = result;
    }
    return failure;
}
}
