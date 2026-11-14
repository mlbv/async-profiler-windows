/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
// Test providers separate imported allocator names from the implementation's CRT.
#ifdef PROVIDER_FORWARDER
#pragma comment(linker, "/export:malloc=ucrtbase.malloc")
#pragma comment(linker, "/export:calloc=ucrtbase.calloc")
#pragma comment(linker, "/export:realloc=ucrtbase.realloc")
#pragma comment(linker, "/export:free=ucrtbase.free")
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <limits>
#include <atomic>

struct alignas(16) Header { std::size_t size; void* allocation; };
static std::atomic<unsigned> getterCalls{0};
extern "C" void* ProviderMalloc(std::size_t size) {
    if (size > (std::numeric_limits<std::size_t>::max)() - sizeof(Header)) { errno = ENOMEM; return nullptr; }
    auto block = static_cast<Header*>(HeapAlloc(GetProcessHeap(), 0, sizeof(Header) + size));
    if (!block) { errno = ENOMEM; return nullptr; }
    block->size = size;
    block->allocation = block;
    SetLastError(0x13579bdf);
    return block + 1;
}
extern "C" void ProviderFree(void* address) {
    if (address) HeapFree(GetProcessHeap(), 0, (static_cast<Header*>(address) - 1)->allocation);
    SetLastError(0x11223344);
}
extern "C" void* ProviderCalloc(std::size_t count, std::size_t size) {
    if (count && size > (std::numeric_limits<std::size_t>::max)() / count) { errno = ENOMEM; return nullptr; }
    auto result = ProviderMalloc(count * size);
    if (result) std::memset(result, 0, count * size);
    return result;
}
extern "C" void* ProviderRealloc(void* address, std::size_t size) {
    if (!address) return ProviderMalloc(size);
    if (!size) { ProviderFree(address); return nullptr; }
    auto result = ProviderMalloc(size);
    if (!result) return nullptr;
    auto oldSize = (static_cast<Header*>(address) - 1)->size;
    std::memcpy(result, address, oldSize < size ? oldSize : size);
    ProviderFree(address);
    return result;
}
static void* alignedRequest(std::size_t alignment, std::size_t size) {
    if (alignment < sizeof(void*) || (alignment & (alignment - 1))) { errno = EINVAL; return nullptr; }
    auto overhead = sizeof(Header) + alignment - 1;
    if (overhead < alignment || size > (std::numeric_limits<std::size_t>::max)() - overhead) { errno = ENOMEM; return nullptr; }
    auto allocation = HeapAlloc(GetProcessHeap(), 0, overhead + size);
    if (!allocation) { errno = ENOMEM; return nullptr; }
    auto address = (reinterpret_cast<std::uintptr_t>(allocation) + overhead) & ~(alignment - 1);
    auto header = reinterpret_cast<Header*>(address) - 1;
    header->size = size; header->allocation = allocation;
    SetLastError(0x13579bdf);
    return reinterpret_cast<void*>(address);
}
extern "C" void* ProviderAlignedAlloc(std::size_t alignment, std::size_t size) {
    if (!alignment || size % alignment) { errno = EINVAL; return nullptr; }
    return alignedRequest(alignment, size);
}
extern "C" int ProviderPosixMemalign(void** output, std::size_t alignment, std::size_t size) {
    if (!output || alignment < sizeof(void*) || (alignment & (alignment - 1))) return EINVAL;
    auto saved = errno;
    auto result = alignedRequest(alignment, size);
    auto error = result ? 0 : ENOMEM;
    errno = saved;
    if (result) *output = result;
    return error;
}
extern "C" __declspec(dllexport) int ProviderError(int value) {
    auto previous = errno;
    if (value >= 0) errno = value;
    return previous;
}
extern "C" int* ProviderErrnoAccessor() {
    getterCalls.fetch_add(1, std::memory_order_relaxed);
    return &errno;
}
extern "C" __declspec(dllexport) unsigned ProviderGetterCalls() { return getterCalls.load(std::memory_order_relaxed); }
extern "C" __declspec(dllexport) std::uintptr_t ProviderGetterAddress() { return reinterpret_cast<std::uintptr_t>(&ProviderErrnoAccessor); }
#pragma comment(linker, "/include:ProviderErrnoAccessor")
#ifdef PROVIDER_EXPOSE_ERRNO
#pragma comment(linker, "/export:_errno=ProviderErrnoAccessor")
#endif
#pragma comment(linker, "/export:malloc=ProviderMalloc")
#pragma comment(linker, "/export:calloc=ProviderCalloc")
#pragma comment(linker, "/export:realloc=ProviderRealloc")
#pragma comment(linker, "/export:free=ProviderFree")
#pragma comment(linker, "/export:aligned_alloc=ProviderAlignedAlloc")
#pragma comment(linker, "/export:posix_memalign=ProviderPosixMemalign")
#endif
