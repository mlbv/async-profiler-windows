/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "vmStructs.h"
#include "windowsCompiledHandlers.h"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>

NMethodUnwindLayout VMStructs::_nmethod_unwind_layout;
int VMStructs::_nmethod_name_offset = -1;
int VMStructs::_blob_size_offset = -1;

namespace {
unsigned checks = 0;
void require(bool value,const char* message) {
    if (!value) { std::fprintf(stderr,"%s\n",message); std::abort(); }
    ++checks;
}
template<class T,class Container> void put(Container& data,size_t offset,T value) {
    std::memcpy(data.data() + offset,&value,sizeof(value));
}
bool immutableTables(unsigned version) { return version >= 25; }
// A PcDesc flag the parser must reject: is_method_handle_invoke through JDK25,
// an unassigned bit after JDK26 renumbered the flags.
std::int32_t rejectedFlags(unsigned version) { return version <= 25 ? 2 : 0x20; }
struct Binding : VMStructs {
    static void set(const NMethodUnwindLayout& layout) {
        _nmethod_unwind_layout = layout;
        _nmethod_name_offset = 104;
        _blob_size_offset = 16;
    }
};
struct Fixture {
    std::array<unsigned char,384> object{};
    std::array<unsigned char,32> root{};
    std::vector<unsigned char> immutable = std::vector<unsigned char>(96);
    NMethodUnwindLayout layout;
    unsigned version;
    explicit Fixture(unsigned v) : version(v) {
        layout.setVersion(v);
        for (auto [name,offset] : {std::pair{"_size",16},{"_frame_size",20},{"_entry_bci",24}})
            layout.observe(name,offset,"int");
        layout.observe("_osr_entry_point",64,"address");
        layout.observe("_scopes_pcs_offset",8,"int");
        layout.observePcDesc("_pc_offset",0,"int"); layout.observePcDesc("_flags",12,"int"); layout.observePcDescSize(16);
        put(object,16,std::int32_t(object.size())); put(object,20,std::int32_t(10)); put(object,24,std::int32_t(-1));
        put(object,104,"nmethod");
        layout.observe("_method",112,"Method*");
        layout.observe("_comp_level",120,"CompLevel");
        layout.observe("_frame_complete_offset",124,immutableTables(v) ? "int16_t" : "int");
        layout.observeMethod("_code",8,v <= 8 || immutableTables(v) ? "nmethod*" : "CompiledMethod*");
        layout.observeMethodSize(root.size());
        put(object,112,reinterpret_cast<std::uintptr_t>(root.data()));
        put(object,120,std::uint32_t(4));
        put(object,124,std::uint32_t(immutableTables(v) ? 0xa5a50005 : 5));
        put(root,8,address());
        std::memset(object.data() + 128,0x90,64);
        if (!immutableTables(v)) {
            layout.observe("_handler_table_offset",0,"int"); layout.observe("_nul_chk_table_offset",4,"int");
            layout.observe("_dependencies_offset",12,"int"); layout.observe("_nmethod_end_offset",72,"int");
            if (v == 8) {
                layout.observe("_code_offset",32,"int"); layout.observe("_data_offset",40,"int");
            } else {
                layout.observe("_code_begin",32,"address"); layout.observe("_code_end",40,"address");
            }
            layout.observe("_entry_point",48,"address"); layout.observe("_verified_entry_point",56,"address");
            layout.observe("_stub_offset",100,"int"); put(object,100,std::int32_t(192));
            put(object,0,std::int32_t(272)); put(object,4,std::int32_t(296));
            put(object,8,std::int32_t(208)); put(object,12,std::int32_t(256)); put(object,72,std::int32_t(296));
            if (v == 8) {
                put(object,32,std::int32_t(128)); put(object,40,std::int32_t(192));
            } else {
                put(object,32,address() + 128); put(object,40,address() + 192);
            }
            put(object,48,address() + 128); put(object,56,address() + 128);
        } else {
            layout.observe("_handler_table_offset",0,"u2"); layout.observe("_nul_chk_table_offset",4,"u2");
            layout.observe("_scopes_data_offset",12,"int"); layout.observe("_immutable_data_size",80,"int");
            layout.observe("_immutable_data",88,"address"); layout.observe("_code_offset",32,"int");
            layout.observe("_data_offset",40,"int"); layout.observe("_entry_offset",48,"u2");
            layout.observe("_verified_entry_offset",56,"u2");
            put(object,0,std::uint16_t(16)); put(object,4,std::uint16_t(16));
            put(object,8,std::int32_t(40)); put(object,12,std::int32_t(88));
            put(object,32,std::int32_t(128)); put(object,40,std::int32_t(192));
            put(object,80,std::int32_t(immutable.size())); put(object,88,reinterpret_cast<std::uintptr_t>(immutable.data()));
        }
        auto* data = !immutableTables(v) ? object.data() : immutable.data();
        auto handlers = !immutableTables(v) ? 272u : 16u, pcs = !immutableTables(v) ? 208u : 40u;
        const std::int32_t table[]{1,10,0,-1,40,0};
        std::memcpy(data + handlers,table,sizeof(table));
        const std::int32_t descriptors[]{-1,0,0,0,10,0,0,0,65,0,0,0};
        std::memcpy(data + pcs,descriptors,sizeof(descriptors));
        Binding::set(layout);
    }
    std::uintptr_t address() const { return reinterpret_cast<std::uintptr_t>(object.data()); }
    NMethod* method() { return reinterpret_cast<NMethod*>(object.data()); }
    const char* snapshot(WindowsProfiler::JavaUnwind::Compiled::Handlers::Snapshot& result,
            NMethodUnwindLayout::CaptureStamp* stamp = nullptr) {
        return method()->snapshotUnwindHandlers(object.data() + 128,64,result,stamp);
    }
};
void test(unsigned version) {
    using WindowsProfiler::JavaUnwind::Compiled::Handlers::Snapshot;
    Snapshot snapshot;
    {
        Fixture fixture(version);
        auto error = fixture.snapshot(snapshot);
        require(!error,error ? error : "NMethod snapshot");
        require(snapshot.address() == fixture.address() + 128 && snapshot.code().size() == 64 && snapshot.entry() == 0
            && snapshot.allocation() == 72 && snapshot.edges().size() == 1 && snapshot.edges()[0].source == 10
            && snapshot.edges()[0].target == 40 && snapshot.edges()[0].callReturn, "Typed NMethod snapshot lost source identity");
        auto old = snapshot.code().data();
        if (version <= 17) {
            put(fixture.object,0,std::int32_t(296));
            Snapshot empty;
            require(!fixture.snapshot(empty) && empty.edges().empty(),"Legacy empty handler snapshot rejected");
            put(fixture.object,0,std::int32_t(272));
        }
        put(fixture.object,24,std::int32_t(0));
        require(fixture.snapshot(snapshot) != nullptr && snapshot.code().data() == old, "Rejected secondary method changed result");
        put(fixture.object,24,std::int32_t(-1));
        auto* metadata = !immutableTables(version) ? fixture.object.data() : fixture.immutable.data();
        auto pcs = !immutableTables(version) ? 208u : 40u;
        std::int32_t flags = rejectedFlags(version);
        std::memcpy(metadata + pcs + 28,&flags,sizeof(flags));
        require(fixture.snapshot(snapshot) != nullptr && snapshot.code().data() == old, "Method-handle return acquired proof");
        flags = 0; std::memcpy(metadata + pcs + 28,&flags,sizeof(flags));
        if (!immutableTables(version)) {
            put(fixture.object,72,std::int32_t(308)); put(fixture.object,296,std::uint32_t(1));
            put(fixture.object,300,std::uint32_t(10)); put(fixture.object,304,std::uint32_t(40));
            require(fixture.snapshot(snapshot) != nullptr && snapshot.code().data() == old, "Implicit exception continuation acquired proof");
            put(fixture.object,296,std::uint32_t(99));
            require(fixture.snapshot(snapshot) != nullptr && snapshot.code().data() == old, "Malformed implicit exception count accepted");
            put(fixture.object,72,std::int32_t(296));
        } else {
            put(fixture.object,4,std::uint16_t(4));
            put(fixture.immutable,4,std::uint32_t(1)); put(fixture.immutable,8,std::uint32_t(10)); put(fixture.immutable,12,std::uint32_t(40));
            require(fixture.snapshot(snapshot) != nullptr && snapshot.code().data() == old, "Immutable implicit continuation acquired proof");
            put(fixture.immutable,4,std::uint32_t(99));
            require(fixture.snapshot(snapshot) != nullptr && snapshot.code().data() == old, "Malformed immutable continuation count accepted");
            put(fixture.immutable,4,std::uint32_t(0));
            require(fixture.snapshot(snapshot) != nullptr && snapshot.code().data() == old, "Exact positive immutable extent acquired zero-probe proof");
            put(fixture.object,4,std::uint16_t(16));
        }
        require(fixture.method()->snapshotUnwindHandlers(fixture.object.data() + 129,63,snapshot) != nullptr
            && snapshot.code().data() == old, "Partial callback range accepted");
        if (!immutableTables(version)) {
            // OpenJDK 8/11 JVMTI reports the code before the stub section;
            // JVMCI 8, labsjdk 11 and JDK 17+ report the whole code range.
            put(fixture.object,100,std::int32_t(176));
            auto insts = fixture.method()->snapshotUnwindHandlers(fixture.object.data() + 128,48,snapshot);
            require(version == 8 || version == 11 ? !insts && snapshot.code().size() == 48 && snapshot.edges().size() == 1
                : insts != nullptr && snapshot.code().size() == 64, "JVMTI instruction range identity");
            require(!fixture.snapshot(snapshot) && snapshot.code().size() == 64, "JVMTI whole code range identity");
            require(fixture.method()->snapshotUnwindHandlers(fixture.object.data() + 128,50,snapshot) != nullptr
                && snapshot.code().size() == 64, "Partial stub range accepted");
            put(fixture.object,100,std::int32_t(192));
        }
        if (immutableTables(version)) {
            put(fixture.object,88,std::uintptr_t(1));
            require(fixture.snapshot(snapshot) != nullptr && snapshot.code().data() == old, "Unreadable immutable data accepted");
        }
        std::memset(fixture.object.data() + 128,0xcc,64);
        fixture.immutable.assign(96,0xcc);
    }
    require(snapshot.code()[0] == 0x90 && snapshot.edges()[0].source == 10 && snapshot.edges()[0].callReturn,
        "Released source storage changed owning NMethod snapshot");
}
void captureStamp(unsigned version) {
    using WindowsProfiler::JavaUnwind::Compiled::Handlers::Snapshot;
    NMethodUnwindLayout::CaptureStamp stamp;
    Snapshot snapshot;
    {
        Fixture fixture(version);
        auto error = fixture.snapshot(snapshot,&stamp);
        require(!error,error ? error : "Capture stamp");
        auto cell = [&](std::uintptr_t address,unsigned width,std::uint64_t expected) {
            unsigned found = 0;
            for (const auto& value : stamp.cells) {
                if (value.address == address) {
                    require(value.width == width && value.expected == expected,"Incorrect typed live cell");
                    ++found;
                }
            }
            require(found == 1,"Missing or duplicated live cell");
        };
        // JDK 8/11 also read the stub offset that ends their JVMTI code range.
        require(stamp.cells.size() == (immutableTables(version) || version == 8 || version == 11 ? 18u : 17u),"Incomplete capture metadata");
        for (unsigned offset : {0u,4u,8u,12u,16u,20u,24u,32u,40u,48u,56u,64u,112u,120u,124u}) {
            unsigned width = 4;
            if (offset == 64 || offset == 112 || (!immutableTables(version) && (offset == 48 || offset == 56))
                    || (version != 8 && !immutableTables(version) && (offset == 32 || offset == 40))) width = sizeof(std::uintptr_t);
            if (immutableTables(version) && (offset == 0 || offset == 4 || offset == 48 || offset == 56 || offset == 124)) width = 2;
            std::uint64_t expected = 0;
            std::memcpy(&expected,fixture.object.data() + offset,width);
            cell(fixture.address() + offset,width,expected);
        }
        if (immutableTables(version)) {
            cell(fixture.address() + 80,4,fixture.immutable.size());
            cell(fixture.address() + 88,sizeof(std::uintptr_t),reinterpret_cast<std::uintptr_t>(fixture.immutable.data()));
        } else {
            cell(fixture.address() + 72,4,296);
            if (version == 8 || version == 11) cell(fixture.address() + 100,4,192);
        }
        cell(reinterpret_cast<std::uintptr_t>(fixture.root.data()) + 8,sizeof(std::uintptr_t),fixture.address());
        auto base = immutableTables(version) ? reinterpret_cast<std::uintptr_t>(fixture.immutable.data()) : fixture.address();
        require(stamp.bytes.size() == 4,"Missing parser byte extents");
        require(stamp.bytes[0].address == fixture.address() + 128 && stamp.bytes[0].bytes.size() == 64
                && stamp.bytes[1].address == base + (immutableTables(version) ? 16 : 272) && stamp.bytes[1].bytes.size() == 24
                && stamp.bytes[2].address == base + (immutableTables(version) ? 40 : 208) && stamp.bytes[2].bytes.size() == 48
                && stamp.bytes[3].address == base + (immutableTables(version) ? 16 : 296) && stamp.bytes[3].bytes.empty(),
                "Capture byte extents differ from parser inputs");
        auto oldCells = stamp.cells.data();
        auto oldBytes = stamp.bytes[0].bytes.data();
        auto oldCode = snapshot.code().data();
        put(fixture.object,24,std::int32_t(0));
        require(fixture.snapshot(snapshot,&stamp) != nullptr && stamp.cells.data() == oldCells
                && stamp.bytes[0].bytes.data() == oldBytes && snapshot.code().data() == oldCode,
                "Rejected layout changed capture outputs");
        put(fixture.object,24,std::int32_t(-1));
        auto* metadata = immutableTables(version) ? fixture.immutable.data() : fixture.object.data();
        auto pcs = immutableTables(version) ? 40 : 208;
        put(fixture.object,112,std::uintptr_t(1));
        require(fixture.snapshot(snapshot,&stamp) != nullptr && stamp.cells.data() == oldCells
                && snapshot.code().data() == oldCode,"Unreadable Method root changed capture outputs");
        require(!fixture.snapshot(snapshot),"Optional root read leaked into snapshot-only capture");
        put(fixture.object,112,reinterpret_cast<std::uintptr_t>(fixture.root.data()));
        auto invalid = fixture.layout;
        invalid.observe("_frame_complete_offset",124,"address");
        Binding::set(invalid);
        require(fixture.snapshot(snapshot,&stamp) != nullptr && stamp.cells.data() == oldCells,
                "Unsupported stamp layout changed output");
        require(!fixture.snapshot(snapshot),"Stamp-only layout changed snapshot behavior");
        Binding::set(fixture.layout);
        std::int32_t flags = rejectedFlags(version);
        std::memcpy(metadata + pcs + 28,&flags,sizeof(flags));
        require(fixture.snapshot(snapshot,&stamp) != nullptr && stamp.cells.data() == oldCells,
                "Parser rejection changed stamp");
        flags = 0; std::memcpy(metadata + pcs + 28,&flags,sizeof(flags));
        put(fixture.root,8,fixture.address() + 1);
        require(!fixture.snapshot(snapshot,&stamp),"Observed Method root value rejected as a lifetime condition");
        cell(reinterpret_cast<std::uintptr_t>(fixture.root.data()) + 8,sizeof(std::uintptr_t),fixture.address() + 1);
        std::memset(fixture.object.data(),0xcc,fixture.object.size());
        fixture.immutable.assign(96,0xcc);
        std::memset(fixture.root.data(),0xcc,fixture.root.size());
    }
    require(stamp.bytes[0].bytes[0] == 0x90 && stamp.bytes[1].bytes[0] == 1 && stamp.bytes[2].bytes[0] == 0xff,
            "Released source storage changed owning capture stamp");
}
void implicitStamp(unsigned version,bool exact) {
    using WindowsProfiler::JavaUnwind::Compiled::Handlers::Snapshot;
    Fixture fixture(version);
    if (immutableTables(version)) {
        put(fixture.object,4,std::uint16_t(0));
        put(fixture.immutable,0,std::uint32_t(1));
        put(fixture.immutable,4,std::uint32_t(10)); put(fixture.immutable,8,std::uint32_t(40));
    } else {
        put(fixture.object,72,std::int32_t(fixture.object.size()));
        if (exact) {
            fixture.layout.observe("_speculations_offset",96,"int");
            put(fixture.object,96,std::int32_t(312));
            put(fixture.object,296,std::uint32_t(1));
            put(fixture.object,300,std::uint32_t(10)); put(fixture.object,304,std::uint32_t(40));
            Binding::set(fixture.layout);
        } else {
            std::memset(fixture.object.data() + 296,0xa5,fixture.object.size() - 296);
            put(fixture.object,296,std::uint32_t(0));
        }
    }
    Snapshot snapshot;
    NMethodUnwindLayout::CaptureStamp stamp;
    auto error = fixture.snapshot(snapshot,&stamp);
    require(!error,error ? error : "Implicit capture stamp");
    auto& bytes = stamp.bytes.back();
    require(bytes.address == (immutableTables(version) ? reinterpret_cast<std::uintptr_t>(fixture.immutable.data()) : fixture.address() + 296)
            && bytes.bytes.size() == (exact ? 16u : 4u)
            && snapshot.faults().size() == (exact ? 1u : 0u),"Incorrect exact/probed implicit extent");
    if (!exact) require(bytes.bytes == std::vector<unsigned char>(4),"Zero probe included unrelated suffix bytes");
}
void implicitProof(unsigned version) {
    using WindowsProfiler::JavaUnwind::Compiled::Handlers::Snapshot;
    Snapshot snapshot;
    {
        Fixture fixture(version);
        std::memset(fixture.object.data() + 296,0xa5,fixture.object.size() - 296);
        put(fixture.object,72,std::int32_t(fixture.object.size()));
        put(fixture.object,296,std::uint32_t(0));
        require(!fixture.snapshot(snapshot),"Unknown-end zero suffix rejected");
        auto reject = [&](const char* message) {
            auto old = snapshot.code().data();
            require(fixture.snapshot(snapshot) != nullptr && snapshot.code().data() == old,message);
        };
        for (auto value : {1u,UINT32_MAX}) {
            put(fixture.object,296,value);
            reject("Unknown-end nonzero suffix acquired proof");
        }
        put(fixture.object,296,std::uint32_t(0));
        for (int size = 1; size < 4; ++size) {
            put(fixture.object,72,std::int32_t(296 + size));
            reject("Unknown-end short suffix acquired proof");
        }
        put(fixture.object,72,std::int32_t(300));
        require(!fixture.snapshot(snapshot),"Exactly four owned zero bytes rejected");
        put(fixture.object,72,std::int32_t(295));
        reject("Implicit upper bound before begin accepted");
        put(fixture.object,72,std::int32_t(fixture.object.size() + 1));
        reject("Implicit upper bound outside owned object accepted");
        put(fixture.object,72,std::int32_t(fixture.object.size()));
        fixture.layout.observe("_speculations_offset",96,"int");
        Binding::set(fixture.layout);
        put(fixture.object,96,std::int32_t(296));
        put(fixture.object,296,std::uint32_t(UINT32_MAX));
        require(!fixture.snapshot(snapshot),"Exact empty extent read a following nonzero suffix");
        put(fixture.object,296,std::uint32_t(0));
        for (int size : {1,4,8}) {
            put(fixture.object,96,std::int32_t(296 + size));
            reject("Exact positive extent acquired zero-probe proof");
        }
        put(fixture.object,96,std::int32_t(295));
        reject("Observed exact endpoint before begin accepted");
        put(fixture.object,96,std::int32_t(fixture.object.size() + 1));
        reject("Observed exact endpoint outside upper bound accepted");
        put(fixture.object,96,std::int32_t(300));
        put(fixture.object,72,std::int32_t(296));
        reject("Observed exact endpoint beyond nmethod end accepted");
        put(fixture.object,72,std::int32_t(fixture.object.size()));
        put(fixture.object,96,std::int32_t(296));
        fixture.layout.observe("_speculations_offset",96,"address");
        Binding::set(fixture.layout);
        reject("Malformed observed endpoint downgraded to an unknown-end probe");
        std::memset(fixture.object.data(),0xcc,fixture.object.size());
    }
    require(snapshot.code().size() == 64 && snapshot.code()[0] == 0x90
            && snapshot.edges().size() == 1 && snapshot.edges()[0].callReturn,
            "Released zero-probe source changed owning snapshot");
}
}
int main() {
    for (unsigned version : {8u,11u,17u,21u,25u,26u,27u}) test(version);
    implicitProof(8); implicitProof(11); implicitProof(17); implicitProof(21);
    for (unsigned version : {8u,11u,17u,21u,25u,26u,27u}) {
        captureStamp(version); implicitStamp(version,true);
        if (!immutableTables(version)) implicitStamp(version,false);
    }
    std::printf("NMETHOD_HANDLER_SNAPSHOT_OK checks=%u versions=8,11,17,21,25,26,27 exactCallback=1 owningCode=1 typedEdges=1\n",checks);
}
