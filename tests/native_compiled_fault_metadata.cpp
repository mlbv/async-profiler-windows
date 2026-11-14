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
#include <utility>

NMethodUnwindLayout VMStructs::_nmethod_unwind_layout;
int VMStructs::_nmethod_name_offset = -1;
int VMStructs::_blob_size_offset = -1;

using namespace WindowsProfiler::JavaUnwind::Compiled;
namespace {
unsigned checks;
void require(bool value,const char* message) {
    ++checks;
    if (!value) { std::fprintf(stderr,"COMPILED_FAULT_METADATA_FAILURE %s\n",message); std::abort(); }
}
template<class Container,class T> void put(Container& bytes,size_t offset,T value) {
    std::memcpy(bytes.data() + offset,&value,sizeof(value));
}
void success(const char* error) { require(!error,error ? error : "Fault snapshot rejected"); }
void identity(const Handlers::Snapshot& snapshot) {
    require(snapshot.faults().size() == 2 && snapshot.faults()[0].source == 0 && snapshot.faults()[0].target == 24
            && snapshot.faults()[1].source == 9 && snapshot.faults()[1].target == 40,
            "Implicit fault offsets changed");
}
struct ParserFixture {
    std::vector<unsigned char> code = std::vector<unsigned char>(64,0x90), descriptors = std::vector<unsigned char>(48);
    std::vector<unsigned char> implicit = std::vector<unsigned char>(24);
    explicit ParserFixture() {
        put(descriptors,0,std::int32_t(-1)); put(descriptors,16,std::int32_t(14)); put(descriptors,32,std::int32_t(65));
        put(implicit,0,std::uint32_t(2)); put(implicit,4,std::uint32_t(0)); put(implicit,8,std::uint32_t(24));
        put(implicit,12,std::uint32_t(9)); put(implicit,16,std::uint32_t(40)); put(implicit,20,std::uint32_t(0xfedcba98));
    }
    Handlers::Source source(unsigned version) const {
        return {version,0x12340000,0,56,true,{16,0,12},code,{},descriptors,
                Handlers::ImplicitExceptionProof::Unproved,implicit};
    }
};
template<class Mutate> void rejectParser(unsigned version,Mutate mutate,const char* expected) {
    ParserFixture fixture;
    auto source = fixture.source(version);
    Handlers::Snapshot snapshot;
    success(Handlers::parse(source,snapshot));
    auto code = snapshot.code().data();
    auto faults = snapshot.faults().data();
    mutate(fixture,source);
    auto error = Handlers::parse(source,snapshot);
    require(error && !std::strcmp(error,expected),error ? error : "Invalid implicit metadata accepted");
    require(snapshot.code().data() == code && snapshot.faults().data() == faults && snapshot.code()[0] == 0x90,
            "Failed parse changed owning snapshot");
    identity(snapshot);
}
void parser(unsigned version) {
    {
        ParserFixture fixture;
        auto source = fixture.source(version);
        Handlers::Snapshot snapshot;
        success(Handlers::parse(source,snapshot));
        identity(snapshot);
        require(snapshot.edges().empty(),"Fault metadata fabricated call-return handlers");
        fixture.code.assign(64,0xcc); fixture.implicit.assign(24,0); fixture.descriptors.assign(48,0);
        auto moved = std::move(snapshot);
        require(moved.code()[0] == 0x90,"Fault snapshot borrowed code bytes");
        identity(moved);
    }
    rejectParser(version,[](auto&,auto& source) { source.exactImplicitExceptions = {}; },"implicit-exception-edges-unsupported");
    for (auto proof : {Handlers::ImplicitExceptionProof::EmptyByExtent,Handlers::ImplicitExceptionProof::EmptyByZeroProbe})
        rejectParser(version,[&](auto&,auto& source) { source.implicitExceptionProof = proof; },"contradictory-implicit-exception-proof");
    rejectParser(version,[](auto& fixture,auto&) { put(fixture.implicit,0,std::uint32_t(0)); },"invalid-implicit-table-size");
    rejectParser(version,[](auto& fixture,auto&) { put(fixture.implicit,0,UINT32_MAX); },"invalid-implicit-table-size");
    rejectParser(version,[](auto&,auto& source) { source.exactImplicitExceptions = source.exactImplicitExceptions.first(3); },
            "invalid-implicit-table-size");
    rejectParser(version,[](auto&,auto& source) { source.exactImplicitExceptions = source.exactImplicitExceptions.first(20); },
            "invalid-implicit-table-size");
    rejectParser(version,[](auto& fixture,auto&) { put(fixture.implicit,0,std::uint32_t(1)); },"invalid-implicit-table-size");
    rejectParser(version,[](auto& fixture,auto& source) {
        fixture.implicit.resize(32); source.exactImplicitExceptions = fixture.implicit;
    },"invalid-implicit-table-size");
    for (auto invalid : {64u,UINT32_MAX}) {
        rejectParser(version,[&](auto& fixture,auto&) { put(fixture.implicit,4,invalid); },"invalid-implicit-table-entry");
        rejectParser(version,[&](auto& fixture,auto&) { put(fixture.implicit,8,invalid); },"invalid-implicit-table-entry");
    }
    rejectParser(version,[](auto& fixture,auto&) { put(fixture.implicit,8,std::uint32_t(0)); },"invalid-implicit-table-entry");
    rejectParser(version,[](auto& fixture,auto&) { put(fixture.implicit,16,std::uint32_t(9)); },"implicit-deoptimization-unsupported");
    rejectParser(version,[](auto& fixture,auto&) { put(fixture.implicit,12,std::uint32_t(0)); },"duplicate-implicit-fault-source");
    // JDK26 removed is_method_handle_invoke (bit 1) and renumbered later PcDesc flags.
    if (version <= 25) rejectParser(version,[](auto& fixture,auto&) { put(fixture.descriptors,28,std::int32_t(2)); },"method-handle-return-unsupported");
    else rejectParser(version,[](auto& fixture,auto&) { put(fixture.descriptors,28,std::int32_t(0x20)); },"unsupported-pcdesc-flags");
    rejectParser(version,[](auto&,auto& source) { source.singleEntry = false; },"secondary-unwind-entry-unsupported");
    {
        ParserFixture fixture;
        fixture.implicit.resize(16); put(fixture.implicit,0,std::uint32_t(1));
        auto source = fixture.source(version);
        Handlers::Snapshot snapshot;
        success(Handlers::parse(source,snapshot));
        require(snapshot.faults().size() == 1 && snapshot.faults()[0].source == 0,"One-entry padded table rejected");
        source.exactImplicitExceptions = {};
        source.implicitExceptionProof = Handlers::ImplicitExceptionProof::EmptyByExtent;
        success(Handlers::parse(source,snapshot));
        require(snapshot.faults().empty(),"Empty replacement retained old fault metadata");
    }
}
bool immutableTables(unsigned version) { return version >= 25; }
struct Binding : VMStructs {
    static void set(const NMethodUnwindLayout& layout) {
        _nmethod_unwind_layout = layout; _nmethod_name_offset = 104; _blob_size_offset = 16;
    }
};
struct RuntimeFixture {
    std::array<unsigned char,384> object{};
    std::vector<unsigned char> immutable = std::vector<unsigned char>(128);
    NMethodUnwindLayout layout;
    unsigned version, nulls, exactEnd;
    explicit RuntimeFixture(unsigned v) : version(v), nulls(immutableTables(v) ? 16 : 296), exactEnd(nulls + 24) {
        layout.setVersion(v);
        for (auto [name,offset] : {std::pair{"_size",16},{"_frame_size",20},{"_entry_bci",24}})
            layout.observe(name,offset,"int");
        layout.observe("_osr_entry_point",64,"address"); layout.observe("_scopes_pcs_offset",8,"int");
        layout.observePcDesc("_pc_offset",0,"int"); layout.observePcDesc("_flags",12,"int"); layout.observePcDescSize(16);
        put(object,16,std::int32_t(object.size())); put(object,20,std::int32_t(8)); put(object,24,std::int32_t(-1));
        put(object,104,"nmethod"); std::memset(object.data() + 128,0x90,64);
        if (!immutableTables(v)) {
            layout.observe("_handler_table_offset",0,"int"); layout.observe("_nul_chk_table_offset",4,"int");
            layout.observe("_dependencies_offset",12,"int"); layout.observe("_nmethod_end_offset",72,"int");
            if (v == 8) {
                layout.observe("_code_offset",32,"int"); layout.observe("_data_offset",40,"int");
                put(object,32,std::int32_t(128)); put(object,40,std::int32_t(192));
            } else {
                layout.observe("_code_begin",32,"address"); layout.observe("_code_end",40,"address");
                put(object,32,address() + 128); put(object,40,address() + 192);
            }
            layout.observe("_entry_point",48,"address"); layout.observe("_verified_entry_point",56,"address");
            layout.observe("_stub_offset",100,"int"); put(object,100,std::int32_t(192));
            put(object,0,std::int32_t(272)); put(object,4,std::int32_t(nulls));
            put(object,8,std::int32_t(208)); put(object,12,std::int32_t(256)); put(object,72,std::int32_t(352));
            put(object,48,address() + 128); put(object,56,address() + 128);
            put(object,96,std::int32_t(exactEnd));
        } else {
            layout.observe("_handler_table_offset",0,"u2"); layout.observe("_nul_chk_table_offset",4,"u2");
            layout.observe("_scopes_data_offset",12,"int"); layout.observe("_immutable_data_size",80,"int");
            layout.observe("_immutable_data",88,"address"); layout.observe("_code_offset",32,"int");
            layout.observe("_data_offset",40,"int"); layout.observe("_entry_offset",48,"u2");
            layout.observe("_verified_entry_offset",56,"u2");
            put(object,0,std::uint16_t(exactEnd)); put(object,4,std::uint16_t(nulls));
            put(object,8,std::int32_t(64)); put(object,12,std::int32_t(112));
            put(object,32,std::int32_t(128)); put(object,40,std::int32_t(192));
            put(object,80,std::int32_t(immutable.size())); put(object,88,reinterpret_cast<std::uintptr_t>(immutable.data()));
        }
        auto* metadata = immutableTables(v) ? immutable.data() : object.data();
        const std::int32_t descriptors[]{-1,0,0,0,14,0,0,0,65,0,0,0};
        const std::int32_t handlers[]{1,14,0,-1,40,0};
        std::memcpy(metadata + (immutableTables(v) ? 64 : 208),descriptors,sizeof(descriptors));
        std::memcpy(metadata + (immutableTables(v) ? exactEnd : 272),handlers,sizeof(handlers));
        const std::uint32_t faults[]{2,0,24,9,40,0xabcdef01};
        std::memcpy(metadata + nulls,faults,sizeof(faults));
        Binding::set(layout);
    }
    std::uintptr_t address() const { return reinterpret_cast<std::uintptr_t>(object.data()); }
    void certifyExact() {
        if (!immutableTables(version)) layout.observe("_speculations_offset",96,"int");
        Binding::set(layout);
    }
    const char* snapshot(Handlers::Snapshot& output) {
        return reinterpret_cast<NMethod*>(object.data())->snapshotUnwindHandlers(object.data() + 128,64,output);
    }
    void faultWord(unsigned index,std::uint32_t value) {
        if (immutableTables(version)) put(immutable,nulls + index * 4,value);
        else put(object,nulls + index * 4,value);
    }
};
void runtime(unsigned version) {
    Handlers::Snapshot snapshot;
    {
        RuntimeFixture fixture(version);
        if (!immutableTables(version)) require(fixture.snapshot(snapshot) != nullptr,"Unknown endpoint acquired positive fault metadata");
        fixture.certifyExact();
        success(fixture.snapshot(snapshot));
        identity(snapshot);
        require(snapshot.edges().size() == 1 && snapshot.edges()[0].source == 14 && snapshot.edges()[0].callReturn,
                "Mixed fault and call-return metadata lost handler");
        auto oldCode = snapshot.code().data();
        auto oldFaults = snapshot.faults().data();
        auto reject = [&](const char* message) {
            require(fixture.snapshot(snapshot) != nullptr && snapshot.code().data() == oldCode
                    && snapshot.faults().data() == oldFaults,message);
            identity(snapshot);
        };
        fixture.faultWord(0,0); reject("Exact positive extent with zero count acquired proof");
        fixture.faultWord(0,UINT32_MAX); reject("Oversized fault count accepted");
        fixture.faultWord(0,2);
        fixture.faultWord(4,9); reject("Implicit deoptimization marker accepted");
        fixture.faultWord(4,40);
        fixture.faultWord(3,0); reject("Duplicate runtime fault source accepted");
        fixture.faultWord(3,9);
        fixture.faultWord(2,64); reject("Fault continuation outside code accepted");
        fixture.faultWord(2,24);
        if (!immutableTables(version)) {
            put(fixture.object,96,std::int32_t(fixture.exactEnd + 8));
            reject("Suffix bytes became an extra implicit table extent");
            put(fixture.object,96,std::int32_t(fixture.exactEnd - 4));
            reject("Unrounded implicit table extent accepted");
            put(fixture.object,96,std::int32_t(fixture.exactEnd));
            fixture.layout.observe("_speculations_offset",96,"address"); Binding::set(fixture.layout);
            reject("Malformed typed endpoint downgraded to unknown");
        } else {
            put(fixture.object,4,std::uint16_t(fixture.nulls + 1));
            reject("Misaligned exact immutable table accepted");
        }
        std::memset(fixture.object.data(),0xcc,fixture.object.size()); fixture.immutable.assign(128,0xcc);
    }
    require(snapshot.code()[0] == 0x90,"Released runtime code changed snapshot");
    identity(snapshot);
}
}
int main() {
    for (unsigned version : {8u,11u,17u,21u,25u,26u,27u}) { parser(version); runtime(version); }
    std::printf("COMPILED_FAULT_METADATA_OK checks=%u versions=8,11,17,21,25,26,27 typedSnapshot=1 exactPositive=1 unchangedFailure=1 owningFaults=1\n",checks);
}
