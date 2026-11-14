/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <algorithm>
#include <cstdint>
#include <limits>
#include <unordered_map>
#include <vector>

namespace WindowsProfiler::JavaUnwind {
enum class Certainty { NotManaged, Proven, Unproven };
struct ProofSpan { std::uint32_t begin, end; bool proven; };

// Callers synchronize updates and queries. Versions retain outgoing-step
// certainty after code unloading, while registration intervals exclude the
// gaps between removing an OS table and publishing its replacement.
class CfiHistory {
    struct Interval { std::uint64_t from, to; };
    struct Area {
        std::uintptr_t begin, end;
        bool metadata;
        std::vector<Interval> intervals;
        std::uint64_t retired = UINT64_MAX;
    };
    struct Version {
        std::uintptr_t begin, end;
        std::uint64_t from = UINT64_MAX, to = UINT64_MAX;
        size_t area;
        std::vector<ProofSpan> spans;
    };
    std::vector<Area> _areas;
    std::vector<Version> _versions;
    std::unordered_map<std::uintptr_t,std::vector<size_t>> _pages;

    bool registered(size_t area, std::uint64_t time) const {
        const auto& intervals = _areas[area].intervals;
        auto found = std::upper_bound(intervals.begin(),intervals.end(),time,
            [](std::uint64_t time,const Interval& interval) { return time < interval.from; });
        return found != intervals.begin() && time < (found - 1)->to;
    }
public:
    static constexpr size_t none = std::numeric_limits<size_t>::max();
    void clear() { _areas.clear(); _versions.clear(); _pages.clear(); }
    size_t addArea(std::uintptr_t begin,std::uintptr_t end,bool metadata) {
        _areas.push_back({begin,end,metadata,{}});
        return _areas.size() - 1;
    }
    void publish(size_t area,std::uint64_t time) { _areas[area].intervals.push_back({time,UINT64_MAX}); }
    void preparePublication(size_t area) { auto& intervals = _areas[area].intervals; intervals.reserve(intervals.size() + 1); }
    void unpublish(size_t area,std::uint64_t time) {
        auto& intervals = _areas[area].intervals;
        if (!intervals.empty() && intervals.back().to == UINT64_MAX) intervals.back().to = time;
    }
    void retireArea(size_t area,std::uint64_t time) { unpublish(area,time); _areas[area].retired = std::min(_areas[area].retired,time); }
    size_t addFunction(size_t area,std::uintptr_t begin,std::uintptr_t end,std::vector<ProofSpan> spans) {
        auto id = _versions.size();
        _versions.push_back({begin,end,UINT64_MAX,UINT64_MAX,area,std::move(spans)});
        for (auto page = begin >> 12, last = (end - 1) >> 12; page <= last; ++page) _pages[page].push_back(id);
        return id;
    }
    void activate(size_t version,std::uint64_t time) {
        if (_versions[version].from == UINT64_MAX) _versions[version].from = time;
    }
    void retire(size_t version,std::uint64_t time) { _versions[version].to = time; }

    Certainty certainty(std::uintptr_t pc,std::uint64_t time,bool knownManaged = false,bool metadataDecoded = true) const {
        size_t selected = none;
        bool managed = knownManaged;
        if (auto page = _pages.find(pc >> 12); page != _pages.end()) {
            for (auto id : page->second) {
                const auto& version = _versions[id];
                if (pc < version.begin || pc >= version.end) continue;
                managed = true;
                if (time < version.from || time >= version.to) continue;
                if (selected != none) return Certainty::Unproven;
                selected = id;
            }
        }
        if (selected != none) {
            const auto& version = _versions[selected];
            if (!registered(version.area,time)) return Certainty::Unproven;
            auto offset = static_cast<std::uint32_t>(pc - version.begin);
            auto span = std::upper_bound(version.spans.begin(),version.spans.end(),offset,
                [](std::uint32_t offset,const ProofSpan& span) { return offset < span.begin; });
            return span != version.spans.begin() && offset < (span - 1)->end && (span - 1)->proven
                ? Certainty::Proven : Certainty::Unproven;
        }
        bool metadata = false;
        for (size_t id = 0; id < _areas.size(); ++id) {
            const auto& area = _areas[id];
            if (pc < area.begin || pc >= area.end) continue;
            if (time >= area.retired) continue;
            managed = true;
            if (!area.metadata || !registered(id,time)) continue;
            if (metadata) return Certainty::Unproven;
            metadata = true;
        }
        if (metadata && metadataDecoded) return Certainty::Proven;
        return managed ? Certainty::Unproven : Certainty::NotManaged;
    }
    size_t versions() const { return _versions.size(); }
};
}
