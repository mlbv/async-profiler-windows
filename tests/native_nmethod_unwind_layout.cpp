/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "nmethodUnwind.h"
#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <utility>

template<typename T,size_t N> static void put(std::array<unsigned char,N>& object,size_t offset,T value) {
    std::memcpy(object.data() + offset,&value,sizeof(value));
}
static NMethodUnwindLayout immutable() {
    NMethodUnwindLayout layout;
    layout.setVersion(25);
    layout.observe("_handler_table_offset",4,"u2");
    layout.observe("_nul_chk_table_offset",2,"u2");
    layout.observe("_scopes_pcs_offset",8,"int");
    layout.observe("_immutable_data_size",12,"int");
    layout.observe("_immutable_data",16,"address");
    return layout;
}
static unsigned snapshotChecks = 0;
static void snapshotBounds(unsigned version) {
    const bool immutableTables = version >= 25;
    std::array<unsigned char,256> object{};
    NMethodUnwindLayout layout;
    layout.setVersion(version);
    constexpr std::uintptr_t address = 0x100000;
    for (auto [name,offset] : {std::pair{"_size",16}, {"_frame_size",20}, {"_entry_bci",24}})
        layout.observe(name,offset,"int");
    layout.observe("_osr_entry_point",64,"address");
    layout.observe("_scopes_pcs_offset",8,"int");
    layout.observePcDesc("_pc_offset",0,"int");
    layout.observePcDesc("_flags",12,"int");
    layout.observePcDescSize(16);
    put<std::int32_t>(object,16,256); put<std::int32_t>(object,20,10); put<std::int32_t>(object,24,-1);
    if (!immutableTables) {
        layout.observe("_handler_table_offset",0,"int"); layout.observe("_nul_chk_table_offset",4,"int");
        layout.observe("_dependencies_offset",12,"int"); layout.observe("_nmethod_end_offset",72,"int");
        if (version == 8) {
            layout.observe("_code_offset",32,"int"); layout.observe("_data_offset",40,"int");
        } else {
            layout.observe("_code_begin",32,"address"); layout.observe("_code_end",40,"address");
        }
        layout.observe("_entry_point",48,"address"); layout.observe("_verified_entry_point",56,"address");
        layout.observe("_stub_offset",100,"int"); put<std::int32_t>(object,100,192);
        put<std::int32_t>(object,0,224); put<std::int32_t>(object,4,248);
        put<std::int32_t>(object,8,192); put<std::int32_t>(object,12,224); put<std::int32_t>(object,72,248);
        if (version == 8) {
            put<std::int32_t>(object,32,128); put<std::int32_t>(object,40,192);
        } else {
            put<std::uintptr_t>(object,32,address + 128); put<std::uintptr_t>(object,40,address + 192);
        }
        put<std::uintptr_t>(object,48,address + 128); put<std::uintptr_t>(object,56,address + 128);
    } else {
        layout.observe("_handler_table_offset",0,"u2"); layout.observe("_nul_chk_table_offset",4,"u2");
        layout.observe("_scopes_data_offset",12,"int"); layout.observe("_immutable_data_size",80,"int");
        layout.observe("_immutable_data",88,"address"); layout.observe("_code_offset",32,"int");
        layout.observe("_data_offset",40,"int"); layout.observe("_entry_offset",48,"u2");
        layout.observe("_verified_entry_offset",56,"u2");
        put<std::uint16_t>(object,0,16); put<std::uint16_t>(object,4,16);
        put<std::int32_t>(object,8,40); put<std::int32_t>(object,12,72);
        put<std::int32_t>(object,32,128); put<std::int32_t>(object,40,192);
        put<std::int32_t>(object,80,80); put<std::uintptr_t>(object,88,0x200000);
    }
    NMethodUnwindLayout::Bounds bounds;
    assert(layout.bounds(object.data(),object.size(),address,bounds));
    assert(bounds.code == address + 128 && bounds.codeSize == 64 && bounds.entry == 0 && bounds.unverifiedEntry == 0 && bounds.allocation == 72
        && bounds.pcDescSize == 16 && bounds.pcDescOffset == 0 && bounds.pcDescFlags == 12);
    assert(bounds.nulls == (immutableTables ? 16u : 248u) && bounds.nullsLimit == bounds.nulls
        && bounds.nullsEndExact == immutableTables && bounds.nullsEnd == (immutableTables ? 16u : 0u));
    {
        // An OSR nmethod qualifies only when its OSR entry is the verified entry.
        auto osr = object;
        put<std::int32_t>(osr,24,4); put<std::uintptr_t>(osr,64,address + 128);
        NMethodUnwindLayout::Bounds osrBounds;
        assert(layout.bounds(osr.data(),osr.size(),address,osrBounds) && osrBounds.entry == bounds.entry
            && osrBounds.code == bounds.code && osrBounds.allocation == bounds.allocation);
        put<std::uintptr_t>(osr,64,0);
        assert(!layout.bounds(osr.data(),osr.size(),address,osrBounds));
        put<std::uintptr_t>(osr,64,address + 136);
        assert(!layout.bounds(osr.data(),osr.size(),address,osrBounds));
        snapshotChecks += 3;
    }
    {
        // A non-OSR nmethod's inline-cache entry precedes its verified entry;
        // its OSR field names no entry.
        auto entries = object;
        auto set = [&](unsigned unverified, unsigned verified) {
            if (immutableTables) { put<std::uint16_t>(entries,48,unverified); put<std::uint16_t>(entries,56,verified); }
            else { put<std::uintptr_t>(entries,48,address + 128 + unverified); put<std::uintptr_t>(entries,56,address + 128 + verified); }
        };
        set(0,16);
        put<std::uintptr_t>(entries,64,address + 129);
        NMethodUnwindLayout::Bounds entryBounds;
        assert(layout.bounds(entries.data(),entries.size(),address,entryBounds) && entryBounds.entry == 16 && entryBounds.unverifiedEntry == 0);
        set(20,16);
        assert(!layout.bounds(entries.data(),entries.size(),address,entryBounds));
        // An OSR nmethod has no inline-cache entry.
        set(0,16);
        put<std::int32_t>(entries,24,4); put<std::uintptr_t>(entries,64,address + 144);
        assert(!layout.bounds(entries.data(),entries.size(),address,entryBounds));
        set(16,16);
        assert(layout.bounds(entries.data(),entries.size(),address,entryBounds) && entryBounds.entry == 16 && entryBounds.unverifiedEntry == 16);
        snapshotChecks += 4;
    }
    auto stamped = layout;
    stamped.observe("_method",104,"Method*");
    stamped.observe("_comp_level",112,"CompLevel");
    stamped.observe("_frame_complete_offset",116,immutableTables ? "int16_t" : "int");
    stamped.observeMethod("_code",8,"nmethod*"); stamped.observeMethodSize(32);
    put<std::uintptr_t>(object,104,0x300000);
    put<std::int32_t>(object,112,4); put<std::uint32_t>(object,116,immutableTables ? 0xa5a5ffff : UINT32_MAX);
    NMethodUnwindLayout::CaptureStamp stamp;
    assert(stamped.bounds(object.data(),object.size(),address,bounds,&stamp) && bounds.methodCode == 0x300008);
    assert(!stamp.cells.empty() && stamp.bytes.empty());
    for (const auto& cell : stamp.cells) {
        assert(cell.width == 1 || cell.width == 2 || cell.width == 4 || cell.width == 8);
        std::uint64_t expected = 0;
        std::memcpy(&expected,object.data() + (cell.address - address),cell.width);
        assert(cell.expected == expected);
    }
    assert(stamp.cells.back().address == address + 116 && stamp.cells.back().width == (immutableTables ? 2u : 4u)
        && stamp.cells.back().expected == (immutableTables ? 0xffffu : UINT32_MAX));
    auto rejectStamp = [&](auto change) {
        auto invalid = stamped; change(invalid);
        auto old = stamp.cells.data();
        assert(invalid.bounds(object.data(),object.size(),address,bounds));
        assert(!invalid.bounds(object.data(),object.size(),address,bounds,&stamp) && stamp.cells.data() == old);
        ++snapshotChecks;
    };
    rejectStamp([](auto& value) { value.observe("_method",104,"address"); });
    rejectStamp([](auto& value) { value.observe("_comp_level",112,"u2"); });
    rejectStamp([](auto& value) { value.observe("_frame_complete_offset",116,"u2"); });
    rejectStamp([](auto& value) { value.observeMethod("_code",8,"address"); });
    rejectStamp([](auto& value) { value.observeMethodSize(8); });
    rejectStamp([](auto& value) { value.observeMethod("_code",UINT64_MAX,"nmethod*"); });
    rejectStamp([](auto& value) { value.observeMethodSize(UINT64_MAX); });
    for (auto method : {std::uintptr_t{0},UINTPTR_MAX - 8}) {
        put<std::uintptr_t>(object,104,method);
        auto old = stamp.cells.data();
        assert(!stamped.bounds(object.data(),object.size(),address,bounds,&stamp) && stamp.cells.data() == old);
        assert(stamped.bounds(object.data(),object.size(),address,bounds));
        ++snapshotChecks;
    }
    put<std::uintptr_t>(object,104,0x300000);
    auto absent = stamp.cells.data();
    assert(!layout.bounds(object.data(),object.size(),address,bounds,&stamp) && stamp.cells.data() == absent);
    auto rejectObject = [&](auto change) {
        auto invalid = object; change(invalid);
        auto sentinel = bounds; sentinel.code = 0xdeadbeef;
        assert(!layout.bounds(invalid.data(),invalid.size(),address,sentinel) && sentinel.code == 0xdeadbeef);
        ++snapshotChecks;
    };
    auto rejectLayout = [&](auto change) {
        auto invalid = layout; change(invalid);
        auto sentinel = bounds; sentinel.code = 0xdeadbeef;
        assert(!invalid.bounds(object.data(),object.size(),address,sentinel) && sentinel.code == 0xdeadbeef);
        ++snapshotChecks;
    };
    rejectObject([](auto& bytes) { put<std::int32_t>(bytes,16,255); });
    rejectObject([](auto& bytes) { put<std::int32_t>(bytes,20,-1); });
    rejectObject([](auto& bytes) { put<std::int32_t>(bytes,20,0x8001); });
    rejectObject([](auto& bytes) { put<std::int32_t>(bytes,24,0); });
    rejectLayout([&](auto& value) { value.setVersion(immutableTables ? 21 : 25); });
    rejectLayout([](auto& value) { value.setVersion(28); });
    rejectLayout([](auto& value) { value.observePcDesc("_flags",12,"u2"); });
    rejectLayout([](auto& value) { value.observePcDesc("_flags",2,"int"); });
    rejectLayout([](auto& value) { value.observePcDescSize(32); value.observePcDescSize(16); });
    rejectLayout([](auto& value) { value.observePcDescSize(UINT64_MAX); });
    if (!immutableTables) {
        assert(bounds.handlers == 224 && bounds.handlersEnd == 248);
        auto exact = layout;
        exact.observe("_speculations_offset",96,"int");
        auto bounded = object;
        put<std::int32_t>(bounded,72,256); put<std::int32_t>(bounded,96,248);
        NMethodUnwindLayout::Bounds exactBounds;
        assert(exact.bounds(bounded.data(),bounded.size(),address,exactBounds) && exactBounds.nullsEndExact
            && exactBounds.nulls == 248 && exactBounds.nullsEnd == 248 && exactBounds.nullsLimit == 256);
        ++snapshotChecks;
        auto rejectExact = [&](auto change) {
            auto invalid = bounded; change(invalid);
            auto sentinel = exactBounds; sentinel.code = 0xdeadbeef;
            assert(!exact.bounds(invalid.data(),invalid.size(),address,sentinel) && sentinel.code == 0xdeadbeef);
            ++snapshotChecks;
        };
        rejectExact([](auto& bytes) { put<std::int32_t>(bytes,96,247); });
        rejectExact([](auto& bytes) { put<std::int32_t>(bytes,96,257); });
        rejectExact([](auto& bytes) { put<std::int32_t>(bytes,72,247); });
        rejectExact([](auto& bytes) { put<std::int32_t>(bytes,72,257); });
        rejectExact([](auto& bytes) { put<std::int32_t>(bytes,96,252); put<std::int32_t>(bytes,72,248); });
        rejectLayout([](auto& value) { value.observe("_speculations_offset",96,"u2"); });
        rejectLayout([](auto& value) { value.observe("_speculations_offset",UINT64_MAX,"int"); });
        // Without an exported speculations offset, adjacent fields end the table at
        // nmethod_end; INCLUDE_JVMCI layouts hold two unexported ints between them.
        auto relocated = [&](int end) {
            NMethodUnwindLayout value;
            value.setVersion(version);
            for (auto [name,offset] : {std::pair{"_size",16}, {"_frame_size",20}, {"_entry_bci",24}}) value.observe(name,offset,"int");
            value.observe("_osr_entry_point",64,"address");
            value.observe("_scopes_pcs_offset",8,"int");
            value.observePcDesc("_pc_offset",0,"int"); value.observePcDesc("_flags",12,"int"); value.observePcDescSize(16);
            value.observe("_handler_table_offset",0,"int"); value.observe("_nul_chk_table_offset",76,"int");
            value.observe("_dependencies_offset",12,"int"); value.observe("_nmethod_end_offset",end,"int");
            if (version == 8) { value.observe("_code_offset",32,"int"); value.observe("_data_offset",40,"int"); }
            else { value.observe("_code_begin",32,"address"); value.observe("_code_end",40,"address"); }
            value.observe("_entry_point",48,"address"); value.observe("_verified_entry_point",56,"address");
            value.observe("_stub_offset",100,"int");
            return value;
        };
        auto moved = object;
        put<std::int32_t>(moved,76,232); put<std::int32_t>(moved,80,256);
        NMethodUnwindLayout::Bounds movedBounds;
        assert(relocated(80).bounds(moved.data(),moved.size(),address,movedBounds) && movedBounds.nullsEndExact
            && movedBounds.nulls == 232 && movedBounds.nullsEnd == 256 && movedBounds.nullsLimit == 256);
        auto jvmci = relocated(88);
        put<std::int32_t>(moved,80,240); put<std::int32_t>(moved,84,248); put<std::int32_t>(moved,88,256);
        assert(jvmci.bounds(moved.data(),moved.size(),address,movedBounds) && movedBounds.nullsEndExact
            && movedBounds.nulls == 232 && movedBounds.nullsEnd == 240 && movedBounds.nullsLimit == 256);
        put<std::int32_t>(moved,84,256);
        assert(relocated(84).bounds(moved.data(),moved.size(),address,movedBounds) && !movedBounds.nullsEndExact
            && movedBounds.nullsLimit == 256);
        put<std::int32_t>(moved,84,248);
        snapshotChecks += 3;
        auto rejectJvmci = [&](auto change) {
            auto invalid = moved; change(invalid);
            auto sentinel = movedBounds; sentinel.code = 0xdeadbeef;
            assert(!jvmci.bounds(invalid.data(),invalid.size(),address,sentinel) && sentinel.code == 0xdeadbeef);
            ++snapshotChecks;
        };
        rejectJvmci([](auto& bytes) { put<std::int32_t>(bytes,80,231); });
        rejectJvmci([](auto& bytes) { put<std::int32_t>(bytes,80,249); });
        rejectJvmci([](auto& bytes) { put<std::int32_t>(bytes,84,257); });
        // JDK 8/11 report JVMTI code up to the stub section; JDK 17/21 report the whole code range.
        auto stubbed = object;
        put<std::int32_t>(stubbed,100,176);
        NMethodUnwindLayout::Bounds stubBounds;
        assert(layout.bounds(stubbed.data(),stubbed.size(),address,stubBounds) && stubBounds.code == address + 128
            && stubBounds.codeSize == 64 && stubBounds.instsSize == (version == 8 || version == 11 ? 48u : 64u) && stubBounds.entry == 0);
        ++snapshotChecks;
        if (version == 8 || version == 11) {
            rejectObject([](auto& bytes) { put<std::int32_t>(bytes,100,128); });
            rejectObject([](auto& bytes) { put<std::int32_t>(bytes,100,193); });
            rejectObject([](auto& bytes) { put<std::int32_t>(bytes,100,-1); });
            rejectLayout([](auto& value) { value.observe("_stub_offset",100,"address"); });
        }
        auto empty = object;
        put<std::int32_t>(empty,0,248);
        NMethodUnwindLayout::Bounds emptyBounds;
        assert(layout.bounds(empty.data(),empty.size(),address,emptyBounds) && emptyBounds.handlers == emptyBounds.handlersEnd);
        ++snapshotChecks;
        rejectObject([](auto& bytes) { put<std::int32_t>(bytes,8,191); });
        rejectObject([](auto& bytes) { put<std::int32_t>(bytes,12,225); });
        rejectObject([](auto& bytes) { put<std::int32_t>(bytes,72,257); });
        rejectObject([](auto& bytes) { put<std::uintptr_t>(bytes,48,address + 129); });
        if (version == 8) {
            rejectObject([](auto& bytes) { put<std::int32_t>(bytes,32,-1); });
            rejectObject([](auto& bytes) { put<std::int32_t>(bytes,40,127); });
            rejectObject([](auto& bytes) { put<std::int32_t>(bytes,40,257); });
            rejectLayout([](auto& value) { value.observe("_code_offset",32,"address"); });
            rejectLayout([](auto& value) { value.observe("_data_offset",40,"u2"); });
        } else {
            rejectObject([](auto& bytes) { put<std::uintptr_t>(bytes,40,address + 127); });
            rejectLayout([](auto& value) { value.observe("_code_end",40,"int"); });
        }
    } else {
        rejectObject([](auto& bytes) { put<std::int32_t>(bytes,32,-1); });
        rejectObject([](auto& bytes) { put<std::int32_t>(bytes,40,257); });
        rejectObject([](auto& bytes) { put<std::uint16_t>(bytes,48,1); });
        rejectObject([](auto& bytes) { put<std::int32_t>(bytes,12,81); });
        rejectObject([](auto& bytes) { put<std::uintptr_t>(bytes,88,UINTPTR_MAX - 79); });
        rejectObject([](auto& bytes) { put<std::uintptr_t>(bytes,88,address); });
        rejectLayout([](auto& value) { value.observe("_handler_table_offset",0,"int"); });
    }
    ++snapshotChecks;
}
int main() {
    std::array<unsigned char,128> object{};
    put<std::uint16_t>(object,2,0x1200); put<std::uint16_t>(object,4,0x1234);
    put<std::uint16_t>(object,6,0xa5a5); // A four-byte read of the u2 field would be wrong.
    put<std::int32_t>(object,8,0x1234); put<std::int32_t>(object,12,0x1234);
    put<std::uintptr_t>(object,16,0x100000);
    auto layout = immutable();
    assert(layout.empty(object.data(),object.size()));
    put<std::int32_t>(object,8,0x1235); assert(!layout.empty(object.data(),object.size()));
    put<std::int32_t>(object,8,0x1234); put<std::int32_t>(object,12,0x1233); assert(!layout.empty(object.data(),object.size()));
    put<std::int32_t>(object,12,-1); assert(!layout.empty(object.data(),object.size()));
    put<std::int32_t>(object,12,0x1234); put<std::int32_t>(object,8,-1); assert(!layout.empty(object.data(),object.size()));
    put<std::int32_t>(object,8,0x1234); put<std::uint16_t>(object,2,0x1235); assert(!layout.empty(object.data(),object.size()));
    put<std::uint16_t>(object,2,0x1200); put<std::uintptr_t>(object,16,0); assert(!layout.empty(object.data(),object.size()));
    put<std::uintptr_t>(object,16,UINTPTR_MAX - 15); assert(!layout.empty(object.data(),object.size()));
    put<std::uintptr_t>(object,16,0x100000); assert(!layout.empty(object.data(),20));
    for (int version : {26,27}) {
        auto supported = layout; supported.setVersion(version); assert(supported.empty(object.data(),object.size()));
    }
    auto wrong = layout; wrong.setVersion(28); assert(!wrong.empty(object.data(),object.size()));
    wrong.setVersion(21); assert(!wrong.empty(object.data(),object.size()));
    wrong = layout; wrong.observe("_handler_table_offset",4,"int"); assert(!wrong.empty(object.data(),object.size()));
    wrong = layout; wrong.observe("_immutable_data_size",12,"u4"); assert(!wrong.empty(object.data(),object.size()));
    wrong = layout; wrong.observe("_scopes_pcs_offset",8,"u2"); assert(!wrong.empty(object.data(),object.size()));
    wrong = layout; wrong.observe("_immutable_data",16,nullptr); assert(!wrong.empty(object.data(),object.size()));
    wrong = layout; wrong.observe("_handler_table_offset",UINT64_MAX,"u2"); assert(!wrong.empty(object.data(),object.size()));
    wrong = layout; wrong.observe("_handler_table_offset",6,"u2"); wrong.observe("_handler_table_offset",4,"u2"); assert(!wrong.empty(object.data(),object.size()));
    put<std::uint16_t>(object,2,0xffff); put<std::uint16_t>(object,4,0xffff);
    put<std::int32_t>(object,8,0xffff); put<std::int32_t>(object,12,0xffff);
    assert(layout.empty(object.data(),object.size()));
    put<std::uint16_t>(object,2,0); put<std::uint16_t>(object,4,0);
    put<std::int32_t>(object,8,0); put<std::int32_t>(object,12,0); put<std::uintptr_t>(object,16,0);
    assert(layout.empty(object.data(),object.size()));
    NMethodUnwindLayout legacy;
    legacy.setVersion(21); legacy.observe("_handler_table_offset",0,"int"); legacy.observe("_nul_chk_table_offset",4,"int");
    put<std::int32_t>(object,0,64); put<std::int32_t>(object,4,64);
    assert(legacy.empty(object.data(),object.size()));
    put<std::int32_t>(object,4,65); assert(!legacy.empty(object.data(),object.size()));
    put<std::int32_t>(object,0,-1); put<std::int32_t>(object,4,-1); assert(!legacy.empty(object.data(),object.size()));
    put<std::int32_t>(object,0,129); put<std::int32_t>(object,4,129); assert(!legacy.empty(object.data(),object.size()));
    put<std::int32_t>(object,0,64); put<std::int32_t>(object,4,64);
    auto split = legacy; split.observe("_immutable_data_size",12,"int"); assert(!split.empty(object.data(),object.size()));
    NMethodUnwindLayout missing; assert(!missing.empty(object.data(),object.size()));
    for (unsigned version : {8,11,17,21,25,26,27}) snapshotBounds(version);
    std::printf("NMETHOD_UNWIND_LAYOUT_OK legacy-int immutable-u2-byte-offsets typed-negative-bounds snapshotChecks=%u\n",snapshotChecks);
}
