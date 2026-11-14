/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "vmStructs.h"
#include "windowsCompiledHandlers.h"
#include <cstring>

const char* NMethod::snapshotUnwindHandlers(const void* code,int codeSize,
        WindowsProfiler::JavaUnwind::Compiled::Handlers::Snapshot& result,NMethodUnwindLayout::CaptureStamp* stamp) {
    using namespace WindowsProfiler::JavaUnwind::Compiled;
    constexpr size_t maximumBytes = 16 * 1024 * 1024;
    if (_nmethod_name_offset < 0 || _blob_size_offset < 0) return "unsupported-handler-nmethod";
    auto copy = [](const void* input,void* output,size_t size) {
        SIZE_T copied = 0;
        return !size || (ReadProcessMemory(GetCurrentProcess(),input,output,size,&copied) && copied == size);
    };
    int objectSize;
    if (!copy(at(_blob_size_offset),&objectSize,sizeof(objectSize)) || objectSize <= 0
            || static_cast<size_t>(objectSize) > maximumBytes) return "handler-nmethod-size";
    std::vector<unsigned char> object(static_cast<size_t>(objectSize));
    if (!copy(this,object.data(),object.size())) return "handler-nmethod-read";
    if (object.size() < sizeof(std::uintptr_t) || static_cast<size_t>(_nmethod_name_offset) > object.size() - sizeof(std::uintptr_t))
        return "unsupported-handler-nmethod";
    std::uintptr_t nameAddress;
    std::memcpy(&nameAddress,object.data() + _nmethod_name_offset,sizeof(nameAddress));
    char methodName[8];
    if (!copy(reinterpret_cast<const void*>(nameAddress),methodName,sizeof(methodName)) || std::memcmp(methodName,"nmethod",8))
        return "unsupported-handler-nmethod";
    NMethodUnwindLayout::Bounds bounds;
    NMethodUnwindLayout::CaptureStamp captured;
    auto address = reinterpret_cast<std::uintptr_t>(this);
    if (!_nmethod_unwind_layout.bounds(object.data(),objectSize,address,bounds,stamp ? &captured : nullptr)) return "handler-nmethod-layout";
    if (bounds.code != reinterpret_cast<std::uintptr_t>(code) || codeSize <= 0
            || (bounds.codeSize != static_cast<unsigned>(codeSize) && bounds.instsSize != static_cast<unsigned>(codeSize)))
        return "handler-nmethod-code-identity";
    bounds.codeSize = static_cast<unsigned>(codeSize);
    if (stamp) {
        std::uintptr_t root;
        if (!copy(reinterpret_cast<const void*>(bounds.methodCode),&root,sizeof(root))) return "handler-method-code-read";
        captured.cells.push_back({bounds.methodCode,sizeof(root),root});
    }
    std::vector<unsigned char> immutable;
    std::span<const unsigned char> data = object;
    if (_nmethod_unwind_layout.immutableTables()) {
        if (bounds.dataSize > maximumBytes - object.size()) return "handler-snapshot-limit";
        immutable.resize(bounds.dataSize);
        if (!copy(reinterpret_cast<const void*>(bounds.data),immutable.data(),immutable.size())) return "handler-immutable-read";
        data = immutable;
    }
    auto nullsBound = bounds.nullsEndExact ? bounds.nullsEnd : bounds.nullsLimit;
    auto implicitBytes = data.subspan(bounds.nulls,nullsBound - bounds.nulls);
    auto implicitProof = Handlers::proveNoImplicitExceptions(implicitBytes,bounds.nullsEndExact);
    std::span<const unsigned char> exactImplicitExceptions;
    if (bounds.nullsEndExact) exactImplicitExceptions = implicitBytes;
    Handlers::Source source{static_cast<unsigned>(_nmethod_unwind_layout.version()),bounds.code,bounds.entry,bounds.allocation,true,
        {bounds.pcDescSize,bounds.pcDescOffset,bounds.pcDescFlags},
        std::span<const unsigned char>(object).subspan(bounds.code - address,bounds.codeSize),
        data.subspan(bounds.handlers,bounds.handlersEnd - bounds.handlers),
        data.subspan(bounds.pcs,bounds.pcsEnd - bounds.pcs),implicitProof,exactImplicitExceptions};
    if (bounds.unverifiedEntry != bounds.entry) source.unverifiedEntry = bounds.unverifiedEntry;
    if (!stamp) return Handlers::parse(source,result);
    Handlers::Snapshot snapshot;
    if (auto error = Handlers::parse(source,snapshot)) return error;
    auto bytes = [&](std::uintptr_t start,std::span<const unsigned char> input) {
        captured.bytes.push_back({start,{input.begin(),input.end()}});
    };
    bytes(bounds.code,source.code);
    bytes(bounds.data + bounds.handlers,source.table);
    bytes(bounds.data + bounds.pcs,source.descriptors);
    if (implicitProof == Handlers::ImplicitExceptionProof::EmptyByZeroProbe) implicitBytes = implicitBytes.first(sizeof(std::uint32_t));
    bytes(bounds.data + bounds.nulls,implicitBytes);
    result = std::move(snapshot);
    *stamp = std::move(captured);
    return nullptr;
}
