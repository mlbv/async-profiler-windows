/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "windowsTracepoint.h"
#include <atomic>
#include <map>

namespace WindowsProfiler::Tracepoint {
struct JoinedStack {
    Record record;
    std::uint64_t counter = 0, lifetime = 0;
};
struct JoinStats {
    std::uint64_t joined = 0, incomplete = 0, orphanContinuations = 0;
    std::uint64_t ambiguous = 0, overflows = 0, pending = 0, retainedBytes = 0;
};
struct JoinLimits {
    // bytes bounds pending entries and their owned schema capacity;
    // completed bounds retained selected and unselected primary identities.
    size_t pending = 4096, bytes = 32 * 1024 * 1024, completed = 65536;
};

// One consumer per capture. MatchId correlates separate kernel/user captures;
// provider, CPU and event timestamps are not correlation identities. The caller
// supplies a nonzero thread-lifetime generation for each selected primary.
// Continuations bind only to a unique capture-scoped (TID, MatchId), preserving
// that original generation even after thread exit. Reuse/cardinality ambiguity
// across any generation fails explicitly.
// TODO: Prove key reuse and one-to-many continuation semantics before relaxing uniqueness.
class StackJoiner {
    struct Key {
        std::uint64_t matchId;
        ULONG tid;
        bool operator<(const Key& other) const;
    };
    struct Pending { Record record; std::uint64_t counter, lifetime; size_t bytes; bool primary; };
    enum class Completion { Selected, Unselected, Discarded };
    struct Completed { std::uint64_t time; Completion kind; };
    JoinLimits limits;
    ULONG pid = 0;
    std::map<Key, Pending> waiting;
    std::map<Key, Completed> completed;
    std::atomic<ULONG> error{0};
    std::atomic<std::uint64_t> joined{0}, incomplete{0}, orphans{0}, ambiguous{0}, overflows{0};
    std::atomic<std::uint64_t> pendingCount{0}, retainedBytes{0};
    static constexpr size_t ENTRY_BYTES = sizeof(Key) + sizeof(Pending) + 4 * sizeof(void*);
    ULONG fail(ULONG code);
    ULONG ambiguousPair();
    ULONG validateStack(const Record& record, bool primary, std::uint64_t& match);
    ULONG reserveCompleted(const Key& key, Completed state);
    ULONG add(Record&& record, std::uint64_t lifetime, std::uint64_t counter,
              bool primary, JoinedStack& result, bool& ready);
public:
    explicit StackJoiner(JoinLimits bounds = {}) : limits(bounds) {}
    void reset(ULONG targetPid);
    // Name/thread/CPU/window/period selection must finish before this call.
    // The original primary's timestamp, CPU, counter and lifetime survive deferred output.
    ULONG primary(Record&& record, std::uint64_t lifetime, std::uint64_t counter,
                  JoinedStack& result, bool& ready);
    // Every decoded primary must take exactly one path: primary() if selected,
    // unselected() otherwise. Filtering must not hide correlation-key reuse.
    // No lifetime, event weight or missing-companion obligation is retained here.
    ULONG unselected(const Record& record);
    ULONG continuation(Record&& record, JoinedStack& result, bool& ready);
    // Unresolved selected primaries fail stop. Unselected companion-only records
    // are diagnosed without charging an event or inventing a missing primary.
    ULONG finish();
    JoinStats stats() const;
};
}
