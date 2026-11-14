/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsCompiledHandlers.h"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>

using namespace WindowsProfiler::JavaUnwind::Compiled;
namespace {
unsigned checks = 0, capturedEdges = 0;
void require(bool value, const char* message) {
    if (!value) { std::fprintf(stderr, "%s\n", message); std::abort(); }
    ++checks;
}
void success(const char* error) { require(!error, error ? error : "handler parse"); }
void integer(std::vector<unsigned char>& bytes, size_t at, std::int32_t value) {
    std::memcpy(bytes.data() + at, &value, sizeof(value));
}
struct Fixture {
    std::vector<unsigned char> code = std::vector<unsigned char>(64, 0x90);
    std::vector<unsigned char> table = std::vector<unsigned char>(48);
    std::vector<unsigned char> pcs = std::vector<unsigned char>(64);
    Fixture() {
        integer(table, 0, 1); integer(table, 4, 10);
        integer(table, 12, -1); integer(table, 16, 40);
        integer(table, 24, 1); integer(table, 28, 20);
        integer(table, 36, 12); integer(table, 40, 50);
        integer(pcs, 0, -1); integer(pcs, 16, 10); integer(pcs, 32, 20); integer(pcs, 48, 65);
    }
    Handlers::Source source(unsigned version = 21) const {
        return {version,0x12340000,0,72,true,{16,0,12},code,table,pcs,Handlers::ImplicitExceptionProof::EmptyByExtent};
    }
};
template<class Change> void reject(Change change, const char* expected) {
    Fixture f;
    auto source = f.source();
    Handlers::Snapshot result;
    success(Handlers::parse(source,result));
    auto oldCode = result.code().data();
    change(f,source);
    auto error = Handlers::parse(source,result);
    require(error && !std::strcmp(error, expected), error ? error : expected);
    require(result.code().data() == oldCode && result.code().size() == 64 && result.edges().size() == 2
        && result.address() == 0x12340000 && result.entry() == 0 && result.allocation() == 72, "Failure changed owning snapshot");
}
void implicitProofs() {
    using Proof = Handlers::ImplicitExceptionProof;
    const std::array<unsigned char,8> suffix{0,0,0,0,0xff,0xff,0xff,0xff};
    require(Handlers::Source{}.implicitExceptionProof == Proof::Unproved,"Default source claimed implicit emptiness");
    require(Handlers::proveNoImplicitExceptions({},false) == Proof::EmptyByExtent,"Empty upper bound lost proof");
    require(Handlers::proveNoImplicitExceptions({},true) == Proof::EmptyByExtent,"Exact empty extent lost proof");
    for (size_t size = 1; size < 4; ++size) {
        auto shortProbe = std::span(suffix).first(size);
        require(Handlers::proveNoImplicitExceptions(shortProbe,false) == Proof::Unproved,"Short probe acquired proof");
    }
    require(Handlers::proveNoImplicitExceptions(std::span(suffix).first(4),false) == Proof::EmptyByZeroProbe,
            "Four-byte zero probe lost proof");
    require(Handlers::proveNoImplicitExceptions(suffix,false) == Proof::EmptyByZeroProbe,"Nonzero suffix bytes changed zero probe");
    for (size_t size : {1u,4u,8u})
        require(Handlers::proveNoImplicitExceptions(std::span(suffix).first(size),true) == Proof::Unproved,
                "Exact positive extent acquired empty proof");
    for (auto count : {1u,UINT32_MAX}) {
        auto nonzero = suffix;
        std::memcpy(nonzero.data(),&count,sizeof(count));
        require(Handlers::proveNoImplicitExceptions(nonzero,false) == Proof::Unproved,"Nonzero unknown probe acquired proof");
    }
    Fixture fixture;
    auto source = fixture.source();
    source.implicitExceptionProof = Handlers::proveNoImplicitExceptions(suffix,false);
    Handlers::Snapshot snapshot;
    success(Handlers::parse(source,snapshot));
    require(snapshot.edges().size() == 2,"Zero-probe certificate lost exceptional edges");
}
void synthetic() {
    implicitProofs();
    for (unsigned version : {8u,11u,17u,21u,25u,26u,27u}) {
        Fixture f;
        Handlers::Snapshot snapshot;
        success(Handlers::parse(f.source(version),snapshot));
        require(snapshot.edges().size() == 2 && snapshot.edges()[0].source == 10 && snapshot.edges()[0].target == 40
            && snapshot.edges()[0].callReturn && snapshot.edges()[1].callReturn, "Exact handler edge identity");
        f.code[0] = 0xcc; f.table.assign(48,0); f.pcs.assign(64,0);
        auto moved = std::move(snapshot);
        require(moved.code()[0] == 0x90 && moved.edges()[0].source == 10 && moved.address() == 0x12340000,
            "Snapshot borrowed source memory or move lost identity");
    }
    {
        Fixture f; Handlers::Snapshot snapshot;
        f.table.resize(24); f.pcs.resize(48); integer(f.pcs, 16, 11); integer(f.pcs, 32, 65);
        success(Handlers::parse(f.source(),snapshot));
        require(snapshot.edges().size() == 1 && !snapshot.edges()[0].callReturn, "Missing exact PcDesc guessed call-return edge");
    }
    {
        Fixture f; Handlers::Snapshot snapshot;
        f.table.resize(40); integer(f.table, 0, 2);
        integer(f.table, 24, 3); integer(f.table, 28, 50); integer(f.table, 32, 1);
        std::memset(f.table.data() + 36, 0xab,4);
        success(Handlers::parse(f.source(),snapshot));
        require(snapshot.edges().size() == 2 && snapshot.edges()[0].source == snapshot.edges()[1].source,
            "Aligned handler padding became a record");
    }
    {
        Fixture f; Handlers::Snapshot snapshot; f.table.clear();
        success(Handlers::parse(f.source(),snapshot));
        require(snapshot.edges().empty(), "Empty handler table acquired edges");
    }
    for (unsigned version : {8u,11u,17u}) {
        Fixture f; f.table.clear();
        auto source = f.source(version);
        Handlers::Snapshot snapshot;
        success(Handlers::parse(source,snapshot));
        require(snapshot.edges().empty() && snapshot.code().size() == f.code.size(),"Legacy empty handler snapshot lost code");
        integer(f.pcs,28,8);
        success(Handlers::parse(source,snapshot));
        if (version <= 11) {
            integer(f.pcs,28,0x10);
            require(Handlers::parse(source,snapshot) != nullptr,"Legacy unknown PcDesc flag accepted");
        }
        auto old = snapshot.code().data();
        integer(f.pcs,28,2);
        require(Handlers::parse(source,snapshot) != nullptr && snapshot.code().data() == old,"Legacy method-handle proof accepted");
        integer(f.pcs,28,0x40);
        require(Handlers::parse(source,snapshot) != nullptr && snapshot.code().data() == old,"Legacy optimized native return accepted");
        integer(f.pcs,28,0);
        source.implicitExceptionProof = Handlers::ImplicitExceptionProof::Unproved;
        require(Handlers::parse(source,snapshot) != nullptr && snapshot.code().data() == old,"Legacy implicit continuation accepted");
        source.implicitExceptionProof = Handlers::ImplicitExceptionProof::EmptyByExtent; source.singleEntry = false;
        require(Handlers::parse(source,snapshot) != nullptr && snapshot.code().data() == old,"Legacy secondary entry accepted");
    }
    for (unsigned version : {26u,27u}) {
        // JDK26 renumbered PcDesc flags after removing is_method_handle_invoke.
        Fixture f;
        auto source = f.source(version);
        Handlers::Snapshot snapshot;
        for (std::int32_t flags : {2,0x10,0x1f}) {
            integer(f.pcs,28,flags);
            success(Handlers::parse(source,snapshot));
            require(snapshot.edges().size() == 2 && snapshot.edges()[1].callReturn,"Renumbered PcDesc flags lost exact call return");
        }
        auto old = snapshot.code().data();
        integer(f.pcs,28,0x20);
        auto error = Handlers::parse(source,snapshot);
        require(error && !std::strcmp(error,"unsupported-pcdesc-flags") && snapshot.code().data() == old,"Unknown JDK26 PcDesc flag accepted");
    }
    reject([](auto&,auto& s) { s.version = 24; }, "unsupported-handler-metadata-version");
    reject([](auto&,auto& s) { s.version = 28; }, "unsupported-handler-metadata-version");
    {
        Fixture f; Handlers::Snapshot snapshot;
        auto source = f.source();
        source.entry = 16; source.unverifiedEntry = 0;
        success(Handlers::parse(source,snapshot));
        require(snapshot.entry() == 16 && snapshot.unverifiedEntry() == std::optional<size_t>(0),"Inline-cache entry was not retained");
        source.unverifiedEntry.reset();
        success(Handlers::parse(source,snapshot));
        require(!snapshot.unverifiedEntry(),"Single-entry snapshot acquired an inline-cache entry");
    }
    reject([](auto&,auto& s) { s.unverifiedEntry = 0; }, "handler-code-bounds");
    reject([](auto&,auto& s) { s.entry = 16; s.unverifiedEntry = 17; }, "handler-code-bounds");
    reject([](auto&,auto& s) { s.singleEntry = false; }, "secondary-unwind-entry-unsupported");
    reject([](auto&,auto& s) { s.address = UINTPTR_MAX - 63; }, "handler-code-bounds");
    reject([](auto&,auto& s) { s.entry = 64; }, "handler-code-bounds");
    reject([](auto&,auto& s) { s.allocation = 73; }, "handler-code-bounds");
    reject([](auto&,auto& s) { s.implicitExceptionProof = Handlers::Source{}.implicitExceptionProof; }, "implicit-exception-edges-unsupported");
    reject([](auto&,auto& s) { s.pcDesc = {0,0,12}; }, "invalid-pcdesc-layout");
    reject([](auto&,auto& s) { s.pcDesc.flags = 2; }, "invalid-pcdesc-layout");
    reject([](auto&,auto& s) { s.descriptors = s.descriptors.first(63); }, "invalid-pcdesc-layout");
    reject([](auto&,auto& s) { s.descriptors = s.descriptors.first(16); }, "missing-pcdesc-sentinels");
    reject([](auto& f,auto&) { integer(f.pcs,0,0); }, "missing-pcdesc-sentinels");
    reject([](auto& f,auto&) { integer(f.pcs,48,30); }, "missing-pcdesc-sentinels");
    reject([](auto& f,auto&) { integer(f.pcs,32,10); }, "unordered-pcdesc-offsets");
    reject([](auto& f,auto&) { integer(f.pcs,32,9); }, "unordered-pcdesc-offsets");
    reject([](auto& f,auto&) { integer(f.pcs,32,-2); }, "unordered-pcdesc-offsets");
    reject([](auto& f,auto&) { integer(f.pcs,32,66); }, "invalid-pcdesc-sentinel");
    reject([](auto& f,auto&) { integer(f.pcs,28,2); }, "method-handle-return-unsupported");
    reject([](auto& f,auto&) { integer(f.pcs,28,0x40); }, "unsupported-pcdesc-flags");
    reject([](auto&,auto& s) { s.table = s.table.first(47); }, "misaligned-handler-table");
    reject([](auto& f,auto&) { integer(f.table,0,0); }, "invalid-handler-subtable");
    reject([](auto& f,auto&) { integer(f.table,0,INT32_MAX); }, "invalid-handler-subtable");
    reject([](auto& f,auto&) { integer(f.table,4,0); }, "invalid-handler-subtable");
    reject([](auto& f,auto&) { integer(f.table,4,64); }, "invalid-handler-subtable");
    reject([](auto& f,auto&) { integer(f.table,8,1); }, "invalid-handler-subtable");
    reject([](auto& f,auto&) { integer(f.table,28,10); }, "duplicate-handler-subtable");
    reject([](auto& f,auto&) { integer(f.table,12,-2); }, "invalid-handler-entry");
    reject([](auto& f,auto&) { integer(f.table,16,-1); }, "invalid-handler-entry");
    reject([](auto& f,auto&) { integer(f.table,16,64); }, "invalid-handler-entry");
    reject([](auto& f,auto&) { integer(f.table,20,-1); }, "invalid-handler-entry");
    reject([](auto& f,auto&) {
        integer(f.table,0,2); integer(f.table,24,-1); integer(f.table,28,50); integer(f.table,32,0);
    }, "duplicate-handler-entry");
}
std::vector<unsigned char> file(const std::string& name) {
    std::ifstream stream(name,std::ios::binary);
    require(stream.good(), "Cannot read saved compiled handler fixture");
    return {std::istreambuf_iterator<char>(stream),std::istreambuf_iterator<char>()};
}
void captured(unsigned version,const char* codePath,const char* tablePath,const char* pcPath) {
    auto code = file(codePath), handlers = file(tablePath), pcs = file(pcPath);
    Handlers::Source source{version,0x12340000,0,88,true,{16,0,12},code,handlers,pcs,Handlers::ImplicitExceptionProof::EmptyByExtent};
    Handlers::Snapshot snapshot;
    success(Handlers::parse(source,snapshot));
    for (const auto& edge : snapshot.edges()) {
        require(edge.callReturn && edge.source < code.size() && edge.target < code.size(), "Saved exact call-return edge lost metadata proof");
        ++capturedEdges;
    }
}
}
int main(int argc,char** argv) {
    require(argc == 1 || argc == 5,"Optional version code table pcdesc fixture arguments");
    synthetic();
    if (argc == 5) captured(static_cast<unsigned>(std::stoul(argv[1])),argv[2],argv[3],argv[4]);
    std::printf("COMPILED_HANDLERS_OK checks=%u capturedEdges=%u versions=8,11,17,21,25,26,27 ownedSnapshot=1 unknownEdges=1\n",checks,capturedEdges);
}
