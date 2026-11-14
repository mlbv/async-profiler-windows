/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsJvmCodeStorage.h"
#include "windowsMutex.h"
#include "vmStructs.h"
#include "vmEntry.h"
#include <algorithm>
#include <atomic>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <vector>

namespace WindowsProfiler::JavaUnwind::VmStorage {
namespace {
using Allocate = jlong (JNICALL*)(JNIEnv*, jobject, jint, jint);
using Free = void (JNICALL*)(JNIEnv*, jobject, jlong);
struct Range { const unsigned char* begin; const unsigned char* end; };
WindowsMutex mutex;
unsigned char* storage = nullptr;
std::atomic<size_t> storageSize{0};
std::atomic<bool> claimed{false}, missing{false};

std::vector<const char*> strings(const std::vector<Range>& ranges, const char* value) {
    std::vector<const char*> result;
    auto length = std::strlen(value) + 1;
    for (const auto& range : ranges) {
        auto cursor = range.begin;
        while (cursor < range.end) {
            auto found = std::search(cursor,range.end,value,value + length);
            if (found == range.end) break;
            result.push_back(reinterpret_cast<const char*>(found));
            cursor = found + length;
        }
    }
    return result;
}

void* binding(const std::vector<Range>& ranges, const char* name, const char* signature) {
    auto names = strings(ranges,name), signatures = strings(ranges,signature);
    void* result = nullptr;
    for (const auto& range : ranges) {
        auto first = (reinterpret_cast<std::uintptr_t>(range.begin) + 7) & ~std::uintptr_t{7};
        auto end = reinterpret_cast<std::uintptr_t>(range.end);
        for (auto address = first; address + sizeof(JNINativeMethod) <= end; address += sizeof(void*)) {
            JNINativeMethod method;
            std::memcpy(&method,reinterpret_cast<const void*>(address),sizeof(method));
            if (std::find(names.begin(),names.end(),method.name) == names.end()
                    || std::find(signatures.begin(),signatures.end(),method.signature) == signatures.end()) continue;
            MEMORY_BASIC_INFORMATION region{};
            if (!VirtualQuery(method.fnPtr,&region,sizeof(region)) || region.State != MEM_COMMIT
                    || region.AllocationBase != VMStructs::libjvm()->imageBase()
                    || !(region.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) continue;
            if (result && result != method.fnPtr) throw std::runtime_error("Ambiguous HotSpot code-storage native binding");
            result = method.fnPtr;
        }
    }
    return result;
}
}

void initialize() {
    std::lock_guard lock(mutex);
    if (storageSize.load(std::memory_order_acquire)) return;
    auto enabled = JVMFlag::find("WhiteBoxAPI");
    if (!enabled || !enabled->get()) return;
    // Use the existing diagnostic allocator only when explicitly enabled by
    // the JVM owner. Native-method records provide both name and JNI ABI;
    // neither VM flags nor machine code are changed here.
    auto image = reinterpret_cast<const unsigned char*>(VMStructs::libjvm()->imageBase());
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    auto pe = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
    auto limit = reinterpret_cast<std::uintptr_t>(image) + pe->OptionalHeader.SizeOfImage;
    std::vector<Range> ranges;
    for (auto cursor = reinterpret_cast<std::uintptr_t>(image); cursor < limit;) {
        MEMORY_BASIC_INFORMATION region{};
        if (!VirtualQuery(reinterpret_cast<const void*>(cursor),&region,sizeof(region))) throw std::runtime_error("Cannot inspect HotSpot native bindings");
        auto end = std::min(limit,reinterpret_cast<std::uintptr_t>(region.BaseAddress) + region.RegionSize);
        if (region.State == MEM_COMMIT && !(region.Protect & (PAGE_NOACCESS | PAGE_GUARD))
                && (region.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            ranges.push_back({reinterpret_cast<const unsigned char*>(cursor),reinterpret_cast<const unsigned char*>(end)});
        }
        if (end <= cursor) throw std::runtime_error("Invalid HotSpot image region");
        cursor = end;
    }
    auto allocate = reinterpret_cast<Allocate>(binding(ranges,"allocateCodeBlob","(II)J"));
    auto release = reinterpret_cast<Free>(binding(ranges,"freeCodeBlob","(J)V"));
    // JDK 8 WhiteBox has no code-blob allocator; ordinary placement still applies.
    if (!allocate || !release) { missing.store(true,std::memory_order_release); return; }
    auto segmented = JVMFlag::find("SegmentedCodeCache");
    // CodeBlobType NonNMethod/All; the hot-heap change that added HotCodeHeapSize
    // inserted MethodHot before them. An absent heap type crashes the VM allocator.
    auto shifted = JVMFlag::find("HotCodeHeapSize") ? 1 : 0;
    auto env = VM::jni();
    auto address = allocate(env,nullptr,65536,(segmented && segmented->get() ? 2 : 3) + shifted);
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe(); env->ExceptionClear();
        throw std::runtime_error("HotSpot diagnostic code-storage allocation failed");
    }
    if (!address) throw std::runtime_error("HotSpot code cache has no space for profiler unwind storage");
    auto blob = reinterpret_cast<NMethod*>(address);
    if (!CodeHeap::contains(blob) || CodeHeap::findNMethod(blob) != blob || std::strcmp(blob->name(),"WB::DummyBlob") != 0) {
        throw std::runtime_error("Unexpected HotSpot code-storage allocation result");
    }
    auto begin = reinterpret_cast<std::uintptr_t>(blob->code());
    auto end = static_cast<std::uintptr_t>(address) + blob->size();
    MEMORY_BASIC_INFORMATION region{};
    if (begin <= static_cast<std::uintptr_t>(address) || end <= begin || end - begin < 4096
            || !VirtualQuery(reinterpret_cast<const void*>(begin),&region,sizeof(region))
            || (region.Protect & PAGE_GUARD)
            || !(region.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
        release(env,nullptr,address);
        throw std::runtime_error("HotSpot code-storage buffer is not writable");
    }
    storage = reinterpret_cast<unsigned char*>(begin);
    // Buffer blobs are not swept as nmethods. Keep this bounded allocation
    // for VM lifetime and reuse it after every registration has been retired.
    storageSize.store(end - begin,std::memory_order_release);
}

void reset() { claimed.store(false,std::memory_order_release); }
bool acquire(std::uintptr_t base, std::uintptr_t limit, unsigned char*& bytes, size_t& size) {
    auto capacity = storageSize.load(std::memory_order_acquire);
    if (!capacity) return false;
    auto address = reinterpret_cast<std::uintptr_t>(storage);
    if (address < base || address + capacity > limit || claimed.exchange(true,std::memory_order_acq_rel)) return false;
    bytes = storage; size = capacity;
    return true;
}
size_t capacity() { return storageSize.load(std::memory_order_acquire); }
bool allocatorMissing() { return missing.load(std::memory_order_acquire); }
}
