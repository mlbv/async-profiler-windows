/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef NMETHOD_UNWIND_H
#define NMETHOD_UNWIND_H

#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

// Typed VM metadata used to bound compiled-method control-flow inputs.
class NMethodUnwindLayout {
public:
    // width is 1, 2, 4 or 8; expected holds zero-extended raw little-endian bits.
    struct LiveCell {
        std::uintptr_t address = 0;
        unsigned width = 0;
        std::uint64_t expected = 0;
    };
    struct LiveBytes {
        std::uintptr_t address = 0;
        std::vector<unsigned char> bytes;
    };
    // Cold-owned semantic inputs, not a unique generation or a lifetime pin.
    // Raw comparisons require an independently active frame for that nmethod.
    struct CaptureStamp {
        std::vector<LiveCell> cells;
        std::vector<LiveBytes> bytes;
    };
private:
    enum class Kind { Missing, Unknown, U2, I2, Int, Address, Method, Code, CompLevel };
    struct Field {
        int offset = -1;
        Kind kind = Kind::Missing;
        void observe(std::uint64_t position,const char* type) {
            Kind next = Kind::Unknown;
            if (type) {
                if (std::strcmp(type,"u2") == 0) next = Kind::U2;
                else if (std::strcmp(type,"int16_t") == 0 || std::strcmp(type,"short") == 0) next = Kind::I2;
                else if (std::strcmp(type,"int") == 0) next = Kind::Int;
                else if (std::strcmp(type,"address") == 0) next = Kind::Address;
                else if (std::strcmp(type,"Method*") == 0) next = Kind::Method;
                else if (std::strcmp(type,"nmethod*") == 0 || std::strcmp(type,"CompiledMethod*") == 0) next = Kind::Code;
                else if (std::strcmp(type,"CompLevel") == 0) next = Kind::CompLevel;
            }
            int value = position <= INT_MAX ? static_cast<int>(position) : -1;
            if (value < 0 || (kind != Kind::Missing && (offset != value || kind != next))) {
                offset = -1; kind = Kind::Unknown;
            } else { offset = value; kind = next; }
        }
        bool valid(Kind expected,int size) const {
            int width = expected == Kind::U2 || expected == Kind::I2 ? 2
                : expected == Kind::Int || expected == Kind::CompLevel ? 4 : sizeof(std::uintptr_t);
            return kind == expected && size >= width && offset >= 0 && offset <= size - width;
        }
        template<typename T> T read(const void* object,std::uintptr_t address = 0,CaptureStamp* stamp = nullptr) const {
            T result;
            auto* bytes = static_cast<const unsigned char*>(object) + offset;
            std::memcpy(&result,bytes,sizeof(result));
            if (stamp) {
                std::uint64_t expected = 0;
                std::memcpy(&expected,bytes,sizeof(result));
                stamp->cells.push_back({address + offset,sizeof(result),expected});
            }
            return result;
        }
    };
    Field _handler, _nulCheck, _scopes, _immutableSize, _immutableData;
    Field _dependencies, _scopesData, _end, _speculations, _stub;
    Field _size, _codeBegin, _codeEnd, _codeOffset, _dataOffset, _entry, _verified, _osr, _bci, _frame;
    Field _pcOffset, _pcFlags, _method, _methodCode, _level, _frameComplete;
    int _version = 0, _pcSize = -1, _methodSize = -1;
    bool _pcSizeInvalid = false, _methodSizeInvalid = false;
    struct HandlerRange {
        std::uintptr_t data = 0;
        int size = 0, first = 0, last = 0, nulCheck = 0;
        bool immutable = false;
    };
    bool handlerRange(const void* object,int objectSize,HandlerRange& result,
            std::uintptr_t address = 0,CaptureStamp* stamp = nullptr) const {
        HandlerRange range;
        range.immutable = _immutableData.kind != Kind::Missing || _immutableSize.kind != Kind::Missing;
        if (!range.immutable) {
            if (!_handler.valid(Kind::Int,objectSize) || !_nulCheck.valid(Kind::Int,objectSize)) return false;
            range.first = _handler.read<std::int32_t>(object,address,stamp);
            range.last = range.nulCheck = _nulCheck.read<std::int32_t>(object,address,stamp);
            range.size = objectSize;
            if (range.first < 0 || range.first > range.last || range.last > objectSize) return false;
        } else {
            // Unsigned byte offsets directly into immutable_data.
            if (!immutableTables() || !_handler.valid(Kind::U2,objectSize) || !_nulCheck.valid(Kind::U2,objectSize)
                    || !_scopes.valid(Kind::Int,objectSize) || !_immutableSize.valid(Kind::Int,objectSize)
                    || !_immutableData.valid(Kind::Address,objectSize)) return false;
            range.first = _handler.read<std::uint16_t>(object,address,stamp);
            range.nulCheck = _nulCheck.read<std::uint16_t>(object,address,stamp);
            range.last = _scopes.read<std::int32_t>(object,address,stamp);
            range.size = _immutableSize.read<std::int32_t>(object,address,stamp);
            range.data = _immutableData.read<std::uintptr_t>(object,address,stamp);
            if (range.size < 0 || range.last < 0 || range.nulCheck > range.first || range.first > range.last
                    || range.last > range.size || (range.size && !range.data)
                    || static_cast<std::uintptr_t>(range.size) > UINTPTR_MAX - range.data) return false;
        }
        result = range;
        return true;
    }
public:
    struct Bounds {
        std::uintptr_t data = 0, code = 0, methodCode = 0;
        // unverifiedEntry equals entry when the nmethod has no inline-cache check.
        // instsSize ends at the JDK 8/11 stub section and equals codeSize elsewhere.
        std::uint32_t dataSize = 0, codeSize = 0, instsSize = 0, entry = 0, unverifiedEntry = 0, allocation = 0;
        std::uint32_t handlers = 0, handlersEnd = 0, pcs = 0, pcsEnd = 0, nulls = 0, nullsLimit = 0, nullsEnd = 0;
        bool nullsEndExact = false;
        unsigned pcDescSize = 0, pcDescOffset = 0, pcDescFlags = 0;
    };
    void setVersion(int version) { _version = version; }
    int version() const { return _version; }
    // JDK25 moved handler, implicit-exception and PcDesc tables to immutable_data.
    bool immutableTables() const { return _version == 25 || _version == 26 || _version == 27; }
    bool supported() const { return _version == 8 || _version == 11 || _version == 17 || _version == 21 || immutableTables(); }
    void observe(const char* name,std::uint64_t offset,const char* type) {
        if (std::strcmp(name,"_handler_table_offset") == 0) _handler.observe(offset,type);
        else if (std::strcmp(name,"_nul_chk_table_offset") == 0) _nulCheck.observe(offset,type);
        else if (std::strcmp(name,"_scopes_pcs_offset") == 0) _scopes.observe(offset,type);
        else if (std::strcmp(name,"_immutable_data_size") == 0) _immutableSize.observe(offset,type);
        else if (std::strcmp(name,"_immutable_data") == 0) _immutableData.observe(offset,type);
        else if (std::strcmp(name,"_dependencies_offset") == 0) _dependencies.observe(offset,type);
        else if (std::strcmp(name,"_scopes_data_offset") == 0) _scopesData.observe(offset,type);
        else if (std::strcmp(name,"_nmethod_end_offset") == 0) _end.observe(offset,type);
        else if (std::strcmp(name,"_speculations_offset") == 0) _speculations.observe(offset,type);
        else if (std::strcmp(name,"_stub_offset") == 0) _stub.observe(offset,type);
        else if (std::strcmp(name,"_size") == 0) _size.observe(offset,type);
        else if (std::strcmp(name,"_code_begin") == 0) _codeBegin.observe(offset,type);
        else if (std::strcmp(name,"_code_end") == 0) _codeEnd.observe(offset,type);
        else if (std::strcmp(name,"_code_offset") == 0) _codeOffset.observe(offset,type);
        else if (std::strcmp(name,"_data_offset") == 0) _dataOffset.observe(offset,type);
        else if (std::strcmp(name,"_entry_point") == 0 || std::strcmp(name,"_entry_offset") == 0) _entry.observe(offset,type);
        else if (std::strcmp(name,"_verified_entry_point") == 0 || std::strcmp(name,"_verified_entry_offset") == 0) _verified.observe(offset,type);
        else if (std::strcmp(name,"_osr_entry_point") == 0) _osr.observe(offset,type);
        else if (std::strcmp(name,"_entry_bci") == 0) _bci.observe(offset,type);
        else if (std::strcmp(name,"_frame_size") == 0) _frame.observe(offset,type);
        else if (std::strcmp(name,"_method") == 0) _method.observe(offset,type);
        else if (std::strcmp(name,"_comp_level") == 0) _level.observe(offset,type);
        else if (std::strcmp(name,"_frame_complete_offset") == 0) _frameComplete.observe(offset,type);
    }
    void observeMethod(const char* name,std::uint64_t offset,const char* type) {
        if (std::strcmp(name,"_code") == 0) _methodCode.observe(offset,type);
    }
    void observeMethodSize(std::uint64_t size) {
        if (!size || size > INT_MAX || (_methodSize >= 0 && size != static_cast<unsigned>(_methodSize))) _methodSizeInvalid = true;
        else _methodSize = static_cast<int>(size);
    }
    void observePcDesc(const char* name,std::uint64_t offset,const char* type) {
        if (std::strcmp(name,"_pc_offset") == 0) _pcOffset.observe(offset,type);
        else if (std::strcmp(name,"_flags") == 0) _pcFlags.observe(offset,type);
    }
    void observePcDescSize(std::uint64_t size) {
        if (!size || size > 256 || (_pcSize >= 0 && size != static_cast<unsigned>(_pcSize))) _pcSizeInvalid = true;
        else _pcSize = static_cast<int>(size);
    }
    bool empty(const void* object,int objectSize) const {
        HandlerRange range;
        return handlerRange(object,objectSize,range) && range.first == range.last;
    }
    // object is a complete stable copy. address identifies its original blob,
    // not the copy's address. No live pointers are dereferenced here.
    // Optional output owns the typed nmethod cells; methodCode identifies the
    // separately bounded Method::_code cell, to be copied by the caller.
    bool bounds(const void* object,int objectSize,std::uintptr_t address,Bounds& result,CaptureStamp* output = nullptr) const {
        CaptureStamp captured;
        auto* stamp = output ? &captured : nullptr;
        if (!supported() || !address || objectSize <= 0
                || static_cast<std::uintptr_t>(objectSize) > UINTPTR_MAX - address
                || !_size.valid(Kind::Int,objectSize) || _size.read<std::int32_t>(object,address,stamp) != objectSize
                || !_frame.valid(Kind::Int,objectSize) || !_osr.valid(Kind::Address,objectSize)
                || !_bci.valid(Kind::Int,objectSize)) return false;
        auto bci = _bci.read<std::int32_t>(object,address,stamp);
        HandlerRange range;
        if (!handlerRange(object,objectSize,range,address,stamp) || range.immutable != immutableTables()) return false;
        Bounds b;
        auto codeFirst = std::uintptr_t{0}, codeLast = std::uintptr_t{0}, instsLast = std::uintptr_t{0}, entry = std::uintptr_t{0}, verified = std::uintptr_t{0};
        int pcs = 0, pcsEnd = 0, nullsLimit = 0, nullsEnd = 0;
        auto offsetCode = [&]() {
            if (!_codeOffset.valid(Kind::Int,objectSize) || !_dataOffset.valid(Kind::Int,objectSize)) return false;
            auto first = _codeOffset.read<std::int32_t>(object,address,stamp), last = _dataOffset.read<std::int32_t>(object,address,stamp);
            if (first < 0 || first >= last || last > objectSize) return false;
            codeFirst = address + first; codeLast = address + last;
            return true;
        };
        if (!immutableTables()) {
            if (!_entry.valid(Kind::Address,objectSize) || !_verified.valid(Kind::Address,objectSize)
                    || !_scopes.valid(Kind::Int,objectSize) || !_dependencies.valid(Kind::Int,objectSize)
                    || !_end.valid(Kind::Int,objectSize)) return false;
            if (_version == 8) {
                if (!offsetCode()) return false;
            } else {
                if (!_codeBegin.valid(Kind::Address,objectSize) || !_codeEnd.valid(Kind::Address,objectSize)) return false;
                codeFirst = _codeBegin.read<std::uintptr_t>(object,address,stamp); codeLast = _codeEnd.read<std::uintptr_t>(object,address,stamp);
            }
            instsLast = codeLast;
            if (_version == 8 || _version == 11) {
                // OpenJDK 8/11 JVMTI CompiledMethodLoad reports insts_begin()/insts_size(),
                // which end where the stub section begins; JVMCI 8 and labsjdk 11 report
                // code_begin()/code_size() like JDK 17+.
                if (!_stub.valid(Kind::Int,objectSize)) return false;
                auto stub = _stub.read<std::int32_t>(object,address,stamp);
                if (stub <= 0 || address + stub <= codeFirst || address + stub > codeLast) return false;
                instsLast = address + stub;
            }
            entry = _entry.read<std::uintptr_t>(object,address,stamp); verified = _verified.read<std::uintptr_t>(object,address,stamp);
            pcs = _scopes.read<std::int32_t>(object,address,stamp); pcsEnd = _dependencies.read<std::int32_t>(object,address,stamp);
            nullsLimit = _end.read<std::int32_t>(object,address,stamp);
            if (pcs < 0 || pcs > pcsEnd || pcsEnd > range.first || range.nulCheck > nullsLimit || nullsLimit > objectSize) return false;
            if (_speculations.kind != Kind::Missing) {
                if (!_speculations.valid(Kind::Int,objectSize)) return false;
                nullsEnd = _speculations.read<std::int32_t>(object,address,stamp);
                if (range.nulCheck > nullsEnd || nullsEnd > nullsLimit) return false;
                b.nullsEndExact = true;
            } else if (_end.offset == _nulCheck.offset + 4) {
                // Adjacent fields: the implicit-exception table ends at nmethod_end.
                nullsEnd = nullsLimit;
                b.nullsEndExact = true;
            } else if (_end.offset == _nulCheck.offset + 12) {
                // INCLUDE_JVMCI nmethods (JVMCI 8, labsjdk 11, JDK 17/21) declare the
                // unexported ints _speculations_offset and _jvmci_data_offset between
                // these two; the table ends where speculations begin.
                Field speculations{_nulCheck.offset + 4,Kind::Int}, jvmciData{_nulCheck.offset + 8,Kind::Int};
                nullsEnd = speculations.read<std::int32_t>(object,address,stamp);
                auto data = jvmciData.read<std::int32_t>(object,address,stamp);
                if (range.nulCheck > nullsEnd || nullsEnd > data || data > nullsLimit) return false;
                b.nullsEndExact = true;
            }
            range.data = address;
        } else {
            if (!offsetCode() || !_entry.valid(Kind::U2,objectSize) || !_verified.valid(Kind::U2,objectSize)
                    || !_scopesData.valid(Kind::Int,objectSize)) return false;
            entry = codeFirst + _entry.read<std::uint16_t>(object,address,stamp); verified = codeFirst + _verified.read<std::uint16_t>(object,address,stamp);
            pcs = range.last; pcsEnd = _scopesData.read<std::int32_t>(object,address,stamp);
            instsLast = codeLast;
            nullsLimit = nullsEnd = range.first;
            b.nullsEndExact = true;
            if (pcs > pcsEnd || pcsEnd > range.size
                    || (range.size && range.data < address + objectSize && address < range.data + range.size)) return false;
        }
        auto osr = _osr.read<std::uintptr_t>(object,address,stamp);
        auto frame = _frame.read<std::int32_t>(object,address,stamp);
        if (codeFirst < address || codeFirst >= codeLast || codeLast > address + objectSize
                || verified < codeFirst || verified >= instsLast || entry < codeFirst || entry > verified
                // An OSR nmethod qualifies only when its OSR entry is the verified entry
                // and it has no inline-cache entry. Other nmethods have no OSR entry.
                || (bci != -1 && (osr != verified || entry != verified)) || frame < 0 || frame > 0x8000
                || (!immutableTables() && codeLast - address > static_cast<unsigned>(pcs))
                || _pcSizeInvalid || _pcSize <= 0 || !_pcOffset.valid(Kind::Int,_pcSize)
                || !_pcFlags.valid(Kind::Int,_pcSize) || (_pcOffset.offset < _pcFlags.offset + 4 && _pcFlags.offset < _pcOffset.offset + 4)) return false;
        b.code = codeFirst; b.codeSize = static_cast<std::uint32_t>(codeLast - codeFirst);
        b.instsSize = static_cast<std::uint32_t>(instsLast - codeFirst);
        b.entry = static_cast<std::uint32_t>(verified - codeFirst); b.unverifiedEntry = static_cast<std::uint32_t>(entry - codeFirst);
        b.allocation = frame ? static_cast<std::uint32_t>(frame * 8 - 8) : 0;
        b.data = range.data; b.dataSize = static_cast<std::uint32_t>(range.size);
        b.handlers = range.first; b.handlersEnd = range.last; b.pcs = pcs; b.pcsEnd = pcsEnd;
        b.nulls = range.nulCheck; b.nullsLimit = nullsLimit; b.nullsEnd = nullsEnd;
        b.pcDescSize = _pcSize; b.pcDescOffset = _pcOffset.offset; b.pcDescFlags = _pcFlags.offset;
        if (stamp) {
            if (!_method.valid(Kind::Method,objectSize)
                    || (!_frameComplete.valid(Kind::I2,objectSize) && !_frameComplete.valid(Kind::Int,objectSize))
                    || (!_level.valid(Kind::CompLevel,objectSize) && !_level.valid(Kind::Int,objectSize))
                    || _methodSizeInvalid || !_methodCode.valid(Kind::Code,_methodSize)) return false;
            auto method = _method.read<std::uintptr_t>(object,address,stamp);
            auto rootOffset = static_cast<unsigned>(_methodCode.offset);
            if (!method || method > UINTPTR_MAX - rootOffset || method + rootOffset > UINTPTR_MAX - sizeof(std::uintptr_t)) return false;
            b.methodCode = method + rootOffset;
            _level.read<std::uint32_t>(object,address,stamp);
            if (_frameComplete.kind == Kind::I2) _frameComplete.read<std::uint16_t>(object,address,stamp);
            else _frameComplete.read<std::uint32_t>(object,address,stamp);
            *output = std::move(captured);
        }
        result = b;
        return true;
    }
};

#endif
