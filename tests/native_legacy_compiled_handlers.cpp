/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "vmStructs.h"
#include "windowsCompiledHandlers.h"
#include "native_compiled_unwind_oracle.h"
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>

NMethodUnwindLayout VMStructs::_nmethod_unwind_layout;
int VMStructs::_nmethod_name_offset = -1;
int VMStructs::_blob_size_offset = -1;

using namespace WindowsProfiler::JavaUnwind::Compiled;
namespace {
unsigned checks;
void require(bool value,const char* message) {
    ++checks;
    if (!value) { std::fprintf(stderr,"LEGACY_COMPILED_HANDLER_FAILURE %s\n",message); std::abort(); }
}
template<class T,class Container> void put(Container& bytes,size_t offset,T value) {
    std::memcpy(bytes.data() + offset,&value,sizeof(value));
}
struct Binding : VMStructs {
    static void set(const NMethodUnwindLayout& layout) {
        _nmethod_unwind_layout = layout; _nmethod_name_offset = 104; _blob_size_offset = 16;
    }
};
struct Fixture {
    std::array<unsigned char,384> object{};
    NMethodUnwindLayout layout;
    static constexpr unsigned codeStart = 128, pcs = 208, handlers = 272, nulls = 312;
    static constexpr unsigned char code[]{
        0x48,0x83,0xec,0x38,
        0x48,0x89,0x6c,0x24,0x30,
        0xe8,0,0,1,0,
        0x48,0x8b,0x6c,0x24,0x30,
        0x48,0x83,0xc4,0x38,0xc3,
        0x90,
        0x48,0x8b,0x6c,0x24,0x30,
        0x48,0x83,0xc4,0x38,0xc3
    };
    explicit Fixture(unsigned version) {
        layout.setVersion(version);
        for (auto [name,offset] : {std::pair{"_handler_table_offset",0},{"_nul_chk_table_offset",4},
                {"_scopes_pcs_offset",8},{"_dependencies_offset",12},{"_size",16},
                {"_frame_size",20},{"_entry_bci",24},{"_nmethod_end_offset",72},{"_stub_offset",100}})
            layout.observe(name,offset,"int");
        for (auto [name,offset] : {std::pair{"_entry_point",48},{"_verified_entry_point",56},{"_osr_entry_point",64}})
            layout.observe(name,offset,"address");
        if (version == 8) {
            layout.observe("_code_offset",32,"int"); layout.observe("_data_offset",40,"int");
            put(object,32,std::int32_t(codeStart)); put(object,40,std::int32_t(codeStart + sizeof(code)));
        } else {
            layout.observe("_code_begin",32,"address"); layout.observe("_code_end",40,"address");
            put(object,32,address() + codeStart); put(object,40,address() + codeStart + sizeof(code));
        }
        layout.observePcDesc("_pc_offset",0,"int"); layout.observePcDesc("_flags",12,"int"); layout.observePcDescSize(16);
        put(object,0,std::int32_t(handlers)); put(object,4,std::int32_t(nulls));
        put(object,8,std::int32_t(pcs)); put(object,12,std::int32_t(pcs + 48));
        put(object,16,std::int32_t(object.size())); put(object,20,std::int32_t(8)); put(object,24,std::int32_t(-1));
        put(object,48,address() + codeStart); put(object,56,address() + codeStart);
        put(object,72,std::int32_t(nulls)); put(object,100,std::int32_t(codeStart + sizeof(code))); put(object,104,"nmethod");
        std::memcpy(object.data() + codeStart,code,sizeof(code));
        const std::int32_t descriptors[]{-1,0,0,0,14,0,0,0,INT_MAX,0,0,0};
        const std::int32_t table[]{2,14,0,-1,24,0,12,25,2};
        std::memcpy(object.data() + pcs,descriptors,sizeof(descriptors));
        std::memcpy(object.data() + handlers,table,sizeof(table));
        put(object,handlers + sizeof(table),std::uint32_t(0xdeadbeef));
        Binding::set(layout);
    }
    std::uintptr_t address() const { return reinterpret_cast<std::uintptr_t>(object.data()); }
    NMethod* method() { return reinterpret_cast<NMethod*>(object.data()); }
    const char* snapshot(Handlers::Snapshot& output) {
        return method()->snapshotUnwindHandlers(object.data() + codeStart,sizeof(code),output);
    }
};
const Span& at(const std::vector<Span>& spans,unsigned pc) {
    auto found = std::find_if(spans.begin(),spans.end(),[&](const auto& span) { return span.begin <= pc && pc < span.end; });
    require(found != spans.end(),"Missing control-flow span");
    return *found;
}
std::vector<Span> flow(const Handlers::Snapshot& snapshot) {
    std::vector<Span> spans;
    Layout layout{snapshot.address(),0,snapshot.entry(),snapshot.allocation(),snapshot.edges().empty(),true};
    require(analyse(snapshot.code().data(),snapshot.code().size(),layout,spans,snapshot.edges()),"Snapshot failed control-flow analysis");
    return spans;
}
void success(Fixture& fixture,Handlers::Snapshot& snapshot) {
    auto error = fixture.snapshot(snapshot);
    require(!error,error ? error : "Typed legacy snapshot rejected");
}
template<class Mutate> void reject(Fixture& fixture,Handlers::Snapshot& snapshot,Mutate mutate,const char* expected) {
    auto object = fixture.object;
    auto old = snapshot.code().data();
    mutate();
    auto error = fixture.snapshot(snapshot);
    require(error && std::strcmp(error,expected) == 0,error ? error : "Invalid legacy snapshot accepted");
    require(snapshot.code().data() == old,"Failed snapshot replaced owning result");
    fixture.object = object;
}
unsigned test(unsigned version) {
    Handlers::Snapshot snapshot;
    unsigned total = 0;
    {
        Fixture fixture(version);
        std::fill(fixture.object.begin() + Fixture::nulls,fixture.object.end(),0xa5);
        put(fixture.object,Fixture::nulls,std::uint32_t(0));
        put(fixture.object,72,std::int32_t(fixture.object.size()));
        success(fixture,snapshot);
        require(snapshot.edges().size() == 2 && snapshot.edges()[0].source == 14 && snapshot.edges()[0].target == 24
                && snapshot.edges()[1].source == 14 && snapshot.edges()[1].target == 25
                && snapshot.edges()[0].callReturn && snapshot.edges()[1].callReturn,"Legacy handler identities changed");
        auto spans = flow(snapshot);
        require(at(spans,24).proven && at(spans,24).returnOffset == 56 && at(spans,24).fpOffset == 48,
                "Exceptional entry used live RBP");
        require(at(spans,30).proven && at(spans,30).fpOffset == -1 && at(spans,34).returnOffset == 0,
                "Exceptional epilogue lost caller state");
        total += contexts(std::vector<unsigned char>(snapshot.code().begin(),snapshot.code().end()),spans);

        put(fixture.object,Fixture::pcs + 16,std::int32_t(13));
        success(fixture,snapshot);
        require(!snapshot.edges()[0].callReturn && !snapshot.edges()[1].callReturn,"Missing exact PcDesc acquired call proof");
        spans = flow(snapshot);
        require(!at(spans,24).proven && at(spans,14).proven,"Unknown exceptional edge corrupted normal path");
        put(fixture.object,Fixture::pcs + 16,std::int32_t(19));
        put(fixture.object,Fixture::handlers + 4,std::int32_t(19));
        success(fixture,snapshot);
        require(snapshot.edges()[0].callReturn,"Exact non-call PcDesc was not retained");
        require(!at(flow(snapshot),24).proven,"Non-call PcDesc acquired exceptional proof");
        put(fixture.object,Fixture::pcs + 16,std::int32_t(14));
        put(fixture.object,Fixture::handlers + 4,std::int32_t(14));
        put(fixture.object,20,std::int32_t(9));
        success(fixture,snapshot);
        require(!at(flow(snapshot),24).proven,"Incorrect declared frame acquired exceptional proof");
        put(fixture.object,20,std::int32_t(8));
        success(fixture,snapshot);

        reject(fixture,snapshot,[&] { put(fixture.object,Fixture::pcs + 28,std::int32_t(2)); },
                "method-handle-return-unsupported");
        reject(fixture,snapshot,[&] { put(fixture.object,Fixture::pcs + 28,std::int32_t(0x40)); },
                "unsupported-pcdesc-flags");
        reject(fixture,snapshot,[&] { put(fixture.object,24,std::int32_t(0)); },"handler-nmethod-layout");
        reject(fixture,snapshot,[&] { put(fixture.object,48,fixture.address() + Fixture::codeStart + 1); },
                "handler-nmethod-layout");
        reject(fixture,snapshot,[&] {
            put(fixture.object,72,std::int32_t(Fixture::nulls + 12));
            put(fixture.object,Fixture::nulls,std::uint32_t(1));
            put(fixture.object,Fixture::nulls + 4,std::uint32_t(14));
            put(fixture.object,Fixture::nulls + 8,std::uint32_t(24));
        },"implicit-exception-edges-unsupported");
        reject(fixture,snapshot,[&] { put(fixture.object,Fixture::handlers,std::int32_t(INT_MAX)); },
                "invalid-handler-subtable");
        reject(fixture,snapshot,[&] { put(fixture.object,Fixture::handlers + 8,std::int32_t(1)); },
                "invalid-handler-subtable");
        reject(fixture,snapshot,[&] { put(fixture.object,Fixture::handlers + 16,std::int32_t(sizeof(Fixture::code))); },
                "invalid-handler-entry");
        reject(fixture,snapshot,[&] { put(fixture.object,Fixture::handlers + 32,std::int32_t(-1)); },
                "invalid-handler-entry");
        reject(fixture,snapshot,[&] {
            put(fixture.object,Fixture::handlers + 24,std::int32_t(-1));
            put(fixture.object,Fixture::handlers + 32,std::int32_t(0));
        },"duplicate-handler-entry");
        reject(fixture,snapshot,[&] { put(fixture.object,0,std::int32_t(Fixture::pcs + 32)); },"handler-nmethod-layout");
        auto old = snapshot.code().data();
        require(fixture.method()->snapshotUnwindHandlers(fixture.object.data() + Fixture::codeStart + 1,
                sizeof(Fixture::code) - 1,snapshot) != nullptr && snapshot.code().data() == old,
                "Partial compiled-method identity accepted");
        std::fill(fixture.object.begin(),fixture.object.end(),0xcc);
    }
    require(snapshot.code().size() == sizeof(Fixture::code) && snapshot.code()[0] == 0x48
            && snapshot.edges().size() == 2 && snapshot.edges()[0].source == 14,
            "Released legacy metadata changed owning snapshot");
    require(at(flow(snapshot),24).proven,"Owning legacy snapshot lost handler proof");
    return total;
}
}
int main() {
    unsigned total = 0;
    for (unsigned version : {8u,11u,17u}) total += test(version);
    std::printf("LEGACY_COMPILED_HANDLERS_OK checks=%u versions=8,11,17 nonempty=1 typedNMethod=1 osContexts=%u\n",checks,total);
}
