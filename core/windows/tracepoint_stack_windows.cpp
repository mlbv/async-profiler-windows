/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsTracepointStack.h"
#include <utility>

namespace WindowsProfiler::Tracepoint {
bool StackJoiner::Key::operator<(const Key& other) const {
    if (tid != other.tid) return tid < other.tid;
    return matchId < other.matchId;
}
ULONG StackJoiner::fail(ULONG code) {
    ULONG expected = 0; error.compare_exchange_strong(expected, code);
    return error.load();
}
ULONG StackJoiner::ambiguousPair() { ambiguous++; return fail(ERROR_INVALID_DATA); }
ULONG StackJoiner::validateStack(const Record& record, bool primary, std::uint64_t& match) {
    if (record.stackCount > record.stacks.size()) return fail(ERROR_INVALID_DATA);
    bool split = false;
    for (size_t i = 0; i < record.stackCount; ++i) {
        if (stackDomain(record.stacks[i]) == StackDomain::Invalid) return fail(ERROR_INVALID_DATA);
        split |= record.stacks[i].matchId != 0;
    }
    match = 0;
    if (!split) return primary ? ERROR_SUCCESS : fail(ERROR_INVALID_DATA);
    match = record.stacks[0].matchId;
    if (!match) return ambiguousPair();
    if (record.stackCount == 2) {
        auto first = stackDomain(record.stacks[0]), second = stackDomain(record.stacks[1]);
        if (!primary || record.stacks[1].matchId != match
                || !((first == StackDomain::Kernel && second == StackDomain::User)
                    || (first == StackDomain::User && second == StackDomain::Kernel))) return ambiguousPair();
    } else if (stackDomain(record.stacks[0]) != (primary ? StackDomain::Kernel : StackDomain::User)) return ambiguousPair();
    return ERROR_SUCCESS;
}
ULONG StackJoiner::reserveCompleted(const Key& key, Completed state) {
    if (completed.contains(key)) return ambiguousPair();
    if (completed.size() >= limits.completed) { overflows++; return fail(ERROR_BUFFER_OVERFLOW); }
    completed.emplace(key, state);
    return ERROR_SUCCESS;
}
void StackJoiner::reset(ULONG targetPid) {
    pid = targetPid; waiting.clear(); completed.clear(); error = 0;
    joined = 0; incomplete = 0; orphans = 0; ambiguous = 0; overflows = 0;
    pendingCount = 0; retainedBytes = 0;
}
ULONG StackJoiner::primary(Record&& record, std::uint64_t lifetime, std::uint64_t counter,
        JoinedStack& result, bool& ready) {
    return add(std::move(record), lifetime, counter, true, result, ready);
}
ULONG StackJoiner::unselected(const Record& record) {
    if (error.load()) return error.load();
    if (!pid || record.pid != pid || record.kind != Kind::Event) return fail(ERROR_INVALID_DATA);
    std::uint64_t match;
    auto code = validateStack(record, true, match); if (code || !match) return code;
    if (!record.tid || !record.time) return fail(ERROR_INVALID_DATA);
    const Key key{match, record.tid};
    auto found = waiting.find(key);
    if (found != waiting.end() && (found->second.primary || record.stackCount == 2
            || found->second.record.time < record.time)) return ambiguousPair();
    auto state = record.stackCount == 2 || found != waiting.end() ? Completion::Discarded : Completion::Unselected;
    code = reserveCompleted(key, {record.time, state}); if (code) return code;
    if (found != waiting.end()) {
        orphans++;
        retainedBytes -= found->second.bytes;
        waiting.erase(found); pendingCount = waiting.size();
    }
    return ERROR_SUCCESS;
}
ULONG StackJoiner::continuation(Record&& record, JoinedStack& result, bool& ready) {
    return add(std::move(record), 0, 0, false, result, ready);
}
ULONG StackJoiner::add(Record&& record, std::uint64_t lifetime, std::uint64_t counter,
        bool primary, JoinedStack& result, bool& ready) {
    ready = false;
    if (error.load()) return error.load();
    if (!pid || record.pid != pid || !record.tid || (primary && !lifetime) || !record.time
            || record.kind != (primary ? Kind::Event : Kind::Continuation) || (primary && !counter)) return fail(ERROR_INVALID_DATA);
    if (!primary && !continuationDescriptor(record.provider, record.descriptor)) return fail(ERROR_NOT_SUPPORTED);
    std::uint64_t match;
    auto code = validateStack(record, primary, match); if (code) return code;
    if (!match) {
        result = {std::move(record), counter, lifetime}; ready = true; return ERROR_SUCCESS;
    }
    const Key key{match, record.tid};
    auto seen = completed.find(key);
    if (seen != completed.end()) {
        if (primary || seen->second.kind != Completion::Unselected || record.time < seen->second.time) return ambiguousPair();
        seen->second.kind = Completion::Discarded; orphans++;
        return ERROR_SUCCESS;
    }
    if (record.stackCount == 2) {
        if (waiting.contains(key)) return ambiguousPair();
        code = reserveCompleted(key, {record.time, Completion::Selected}); if (code) return code;
        result = {std::move(record), counter, lifetime}; ready = true; joined++; return ERROR_SUCCESS;
    }
    auto found = waiting.find(key);
    if (found == waiting.end()) {
        if (waiting.size() >= limits.pending || ENTRY_BYTES > limits.bytes
                || record.schema.capacity() > limits.bytes - ENTRY_BYTES
                || retainedBytes.load() > limits.bytes - ENTRY_BYTES - record.schema.capacity()) {
            overflows++; return fail(ERROR_BUFFER_OVERFLOW);
        }
        const auto bytes = ENTRY_BYTES + record.schema.capacity();
        waiting.emplace(key, Pending{std::move(record), counter, lifetime, bytes, primary});
        pendingCount = waiting.size(); retainedBytes += bytes;
        return ERROR_SUCCESS;
    }
    auto& pending = found->second;
    if (pending.primary == primary) return ambiguousPair();
    auto& original = primary ? record : pending.record;
    auto& companion = primary ? pending.record : record;
    if (companion.time < original.time) return ambiguousPair();
    code = reserveCompleted(key, {original.time, Completion::Selected}); if (code) return code;
    if (primary) {
        record.stacks[1] = pending.record.stacks[0]; record.stackCount = 2;
        result = {std::move(record), counter, lifetime};
    } else {
        pending.record.stacks[1] = record.stacks[0]; pending.record.stackCount = 2;
        result = {std::move(pending.record), pending.counter, pending.lifetime};
    }
    retainedBytes -= pending.bytes;
    waiting.erase(found); pendingCount = waiting.size();
    joined++; ready = true; return ERROR_SUCCESS;
}
ULONG StackJoiner::finish() {
    bool missing = false;
    for (const auto& [key, pending] : waiting) {
        if (pending.primary) { incomplete++; missing = true; }
        else orphans++;
    }
    waiting.clear(); pendingCount = 0; retainedBytes = 0;
    return missing ? fail(ERROR_INVALID_DATA) : error.load();
}
JoinStats StackJoiner::stats() const {
    return {joined.load(), incomplete.load(), orphans.load(), ambiguous.load(), overflows.load(),
        pendingCount.load(), retainedBytes.load()};
}
}
