/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsMappedNativeUnwind.h"
#include <array>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <tuple>
#include <utility>

using namespace WindowsProfiler;
namespace {
void require(bool value, const char* message) {
    if (!value) { std::fprintf(stderr, "%s Windows=%lu\n", message, GetLastError()); std::abort(); }
}
void success(const char* error) {
    if (error) { std::fprintf(stderr, "%s Windows=%lu\n", error, GetLastError()); std::abort(); }
}
class Fixture {
    WCHAR _path[MAX_PATH]{};
public:
    HMODULE module = nullptr;
    ULONG text = 0x1000, pdata, xdata, size;
    RUNTIME_FUNCTION primary{}, middle{}, child{};
    bool nested;
    explicit Fixture(unsigned version = 1, bool multiple = true, ULONG textSize = 0x1000) : nested(multiple) {
        pdata = text + textSize; xdata = pdata + 0x1000; size = xdata + 0x2000;
        primary = {text, text + 7, xdata};
        middle = {text + 0x40, text + 0x47, xdata + 0x40};
        child = {text + 0x80, text + (nested ? 0x87u : 0x8cu), xdata + 0x80};
        std::vector<unsigned char> file(0x2800);
        IMAGE_DOS_HEADER dos{}; dos.e_magic = IMAGE_DOS_SIGNATURE; dos.e_lfanew = 0x80;
        std::memcpy(file.data(), &dos, sizeof(dos));
        IMAGE_NT_HEADERS64 pe{};
        pe.Signature = IMAGE_NT_SIGNATURE;
        pe.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        pe.FileHeader.NumberOfSections = 3;
        pe.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        pe.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE
            | IMAGE_FILE_DLL | IMAGE_FILE_RELOCS_STRIPPED;
        auto& optional = pe.OptionalHeader;
        optional.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        optional.ImageBase = 0x610000000000;
        optional.SectionAlignment = 0x1000; optional.FileAlignment = 0x200;
        optional.MajorOperatingSystemVersion = 6; optional.MajorSubsystemVersion = 6;
        optional.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
        optional.SizeOfImage = size; optional.SizeOfHeaders = 0x400;
        optional.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION] = {pdata, 3 * sizeof(RUNTIME_FUNCTION)};
        std::memcpy(file.data() + dos.e_lfanew, &pe, sizeof(pe));
        std::array<IMAGE_SECTION_HEADER,3> sections{};
        const std::array<ULONG,3> rvas{text,pdata,xdata}, raw{0x400,0x600,0x800}, rawSize{0x200,0x200,0x2000};
        const char* names[]{".text",".pdata",".xdata"};
        for (size_t index = 0; index < sections.size(); ++index) {
            auto& section = sections[index];
            std::memcpy(section.Name, names[index], std::strlen(names[index]));
            section.VirtualAddress = rvas[index]; section.PointerToRawData = raw[index];
            section.SizeOfRawData = rawSize[index];
            section.Misc.VirtualSize = index == 0 ? textSize : index == 1 ? 0x200u : 0x2000u;
            section.Characteristics = IMAGE_SCN_MEM_READ | (index == 0 ? IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE : IMAGE_SCN_CNT_INITIALIZED_DATA);
        }
        std::memcpy(file.data() + dos.e_lfanew + sizeof(pe), sections.data(), sizeof(sections));
        const unsigned char primaryCode[]{0x53,0x48,0x83,0xec,0x40,0x90,0xc3};
        const unsigned char middleCode[]{0x48,0x89,0x74,0x24,0x20,0x90,0xc3};
        const unsigned char childCode[]{0x48,0x89,0x7c,0x24,0x28,0x90,0xc3};
        std::memcpy(file.data() + 0x400, primaryCode, sizeof(primaryCode));
        std::memcpy(file.data() + 0x440, middleCode, sizeof(middleCode));
        if (!nested) std::memcpy(file.data() + 0x480, middleCode, 5);
        std::memcpy(file.data() + 0x480 + (nested ? 0 : 5), childCode, sizeof(childCode));
        const std::array<RUNTIME_FUNCTION,3> rows{primary,middle,child};
        std::memcpy(file.data() + 0x600, rows.data(), sizeof(rows));
        std::vector<unsigned char> primaryInfo{1,5,2,0,5,0x72,1,0x30};
        std::vector<unsigned char> middleInfo{static_cast<unsigned char>(version | 32),5,2,0,5,0x64,4,0};
        std::vector<unsigned char> childInfo = nested ? std::vector<unsigned char>{static_cast<unsigned char>(version | 32),5,2,0,5,0x74,5,0}
            : std::vector<unsigned char>{static_cast<unsigned char>(version | 32),10,4,0,10,0x74,5,0,5,0x64,4,0};
        auto append = [](auto& bytes, const RUNTIME_FUNCTION& parent) {
            auto offset = bytes.size(); bytes.resize(offset + sizeof(parent));
            std::memcpy(bytes.data() + offset, &parent, sizeof(parent));
        };
        append(middleInfo, primary); append(childInfo, nested ? middle : primary);
        std::memcpy(file.data() + 0x800, primaryInfo.data(), primaryInfo.size());
        std::memcpy(file.data() + 0x840, middleInfo.data(), middleInfo.size());
        std::memcpy(file.data() + 0x880, childInfo.data(), childInfo.size());
        WCHAR temporary[MAX_PATH];
        require(GetTempPathW(MAX_PATH, temporary) && GetTempFileNameW(temporary, L"apu", 0, _path), "Cannot create PE chain fixture");
        auto handle = CreateFileW(_path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
        require(handle != INVALID_HANDLE_VALUE, "Cannot open PE chain fixture");
        DWORD written = 0;
        require(WriteFile(handle, file.data(), static_cast<DWORD>(file.size()), &written, nullptr)
            && written == file.size(), "Cannot write PE chain fixture");
        CloseHandle(handle);
        module = LoadLibraryW(_path);
        require(module != nullptr, "Cannot load PE chain fixture");
    }
    ~Fixture() { unload(); DeleteFileW(_path); }
    unsigned char* at(ULONG rva) const { return reinterpret_cast<unsigned char*>(module) + rva; }
    void unload() { if (module) { require(FreeLibrary(module), "Cannot unload PE fixture"); module = nullptr; } }
    void put(ULONG rva, const void* bytes, size_t length) {
        DWORD old = 0, ignored = 0;
        require(VirtualProtect(at(rva), length, PAGE_READWRITE, &old), "Cannot make owned PE fixture writable");
        std::memcpy(at(rva), bytes, length);
        require(VirtualProtect(at(rva), length, old, &ignored), "Cannot restore owned PE fixture protection");
    }
    template<class T> void put(ULONG rva, const T& value) { put(rva, &value, sizeof(value)); }
    const char* snapshot(NativeUnwind::SourceSnapshot& out, size_t probe = 0) const {
        return NativeUnwind::snapshotMapped(module, size, child, reinterpret_cast<DWORD64>(at(child.BeginAddress + static_cast<ULONG>(probe))), 5, out);
    }
};
unsigned rejections = 0, checked = 0;
void rejected(const char* error, const char* expected) {
    require(error && !std::strcmp(error, expected), error ? error : "Malformed mapped PE accepted");
    ++rejections;
}
void rejectChange(const std::function<void(Fixture&)>& mutate, const char* expected) {
    Fixture fixture;
    NativeUnwind::SourceSnapshot snapshot;
    success(fixture.snapshot(snapshot));
    auto before = snapshot.source();
    auto originalCode = std::vector<unsigned char>(before.code.begin(), before.code.end());
    auto originalUnwind = std::vector<unsigned char>(before.unwind.begin(), before.unwind.end());
    mutate(fixture);
    rejected(fixture.snapshot(snapshot), expected);
    auto after = snapshot.source();
    require(after.code.data() == before.code.data() && after.unwind.data() == before.unwind.data()
        && std::equal(after.code.begin(), after.code.end(), originalCode.begin())
        && std::equal(after.unwind.begin(), after.unwind.end(), originalUnwind.begin()), "Failed snapshot changed published output");
}
void negatives() {
    rejectChange([](auto& f) { auto row = f.primary; row.EndAddress = row.BeginAddress; f.put(f.xdata + 0x48, row); },
        "mapped-unwind-function-bounds");
    rejectChange([](auto& f) { auto row = f.primary; row.BeginAddress = f.pdata; row.EndAddress = f.pdata + 7; f.put(f.xdata + 0x48, row); },
        "mapped-unwind-function-bounds");
    rejectChange([](auto& f) { auto row = f.primary; row.EndAddress = f.pdata + 1; f.put(f.xdata + 0x48, row); },
        "mapped-unwind-function-bounds");
    rejectChange([](auto& f) { auto row = f.primary; row.UnwindData += 1; f.put(f.xdata + 0x48, row); },
        "mapped-unwind-function-bounds");
    rejectChange([](auto& f) { auto row = f.primary; row.UnwindData = f.size + 0x3000; f.put(f.xdata + 0x48, row); },
        "mapped-unwind-function-bounds");
    rejectChange([](auto& f) { auto row = f.primary; row.UnwindData = f.size - 4; f.put(f.xdata + 0x48, row);
            const unsigned char info[]{33,0,0,0}; f.put(row.UnwindData, info); },
        "mapped-unwind-metadata-bounds");
    rejectChange([](auto& f) { unsigned char value = 3; f.put(f.xdata, value); }, "unsupported-unwind-version");
    rejectChange([](auto& f) { unsigned char value = 9; f.put(f.xdata, value); }, "language-handler-needs-forwarding");
    rejectChange([](auto& f) { unsigned char value = 65; f.put(f.xdata, value); }, "invalid-unwind-flags");
    rejectChange([](auto& f) { unsigned char value = 41; f.put(f.xdata, value); }, "invalid-unwind-flags");
    rejectChange([](auto& f) { f.put(f.xdata + 0x48, f.child); }, "cyclic-unwind-chain");
    rejectChange([](auto& f) { f.put(f.xdata + 0x88, f.child); }, "cyclic-unwind-chain");
    rejectChange([](auto& f) { auto row = f.child; --row.EndAddress; f.put(f.pdata + 2 * sizeof(row), row); },
        "mapped-unwind-selected-row-mismatch");
    rejectChange([](auto& f) { DWORD old; require(VirtualProtect(f.at(f.xdata), 4096, PAGE_NOACCESS, &old), "Protect fixture failed"); },
        "mapped-unwind-function-bounds");
    rejectChange([](auto& f) {
        for (size_t index = 0; index <= NativeUnwind::MAX_MAPPED_CHAIN; ++index) {
            auto rva = f.xdata + 0x100 + static_cast<ULONG>(index * 16);
            const unsigned char info[]{33,1,0,0}; f.put(rva, info);
            RUNTIME_FUNCTION next{f.text, f.text + 7, rva + 16}; f.put(rva + 4, next);
        }
        RUNTIME_FUNCTION next{f.text, f.text + 7, f.xdata + 0x100}; f.put(f.xdata + 0x88, next);
    }, "mapped-unwind-chain-limit");
    {
        Fixture f(1, true, static_cast<ULONG>(NativeUnwind::MAX_MAPPED_SNAPSHOT_BYTES + 0x1000));
        NativeUnwind::SourceSnapshot snapshot;
        auto parent = f.primary; parent.EndAddress = f.pdata;
        f.put(f.xdata + 0x48, parent);
        rejected(f.snapshot(snapshot), "mapped-unwind-snapshot-limit");
    }
    {
        Fixture f;
        NativeUnwind::SourceSnapshot snapshot;
        rejected(NativeUnwind::snapshotMapped(f.module, f.size, f.child, reinterpret_cast<DWORD64>(&negatives), 5, snapshot),
            "mapped-unwind-probe-bounds");
        rejected(NativeUnwind::snapshotMapped(f.module, f.size - 0x1000, f.child, reinterpret_cast<DWORD64>(f.at(f.child.BeginAddress)), 5, snapshot),
            "mapped-unwind-image-headers");
        rejected(NativeUnwind::snapshotMapped(reinterpret_cast<HMODULE>(f.at(f.text)), f.size, f.child,
            reinterpret_cast<DWORD64>(f.at(f.child.BeginAddress)), 5, snapshot), "mapped-unwind-image-headers");
        auto module = f.module;
        auto pc = reinterpret_cast<DWORD64>(f.at(f.child.BeginAddress));
        f.unload();
        rejected(NativeUnwind::snapshotMapped(module, f.size, f.child, pc, 5, snapshot), "mapped-unwind-image-headers");
    }
}
CONTEXT unwind(CONTEXT context, DWORD64 image, RUNTIME_FUNCTION* function, DWORD64& frame) {
    void* data = nullptr;
    RtlVirtualUnwind(UNW_FLAG_NHANDLER, image, context.Rip, function, &context, &data, &frame, nullptr);
    return context;
}
void nativeContexts(unsigned version, bool nested) {
    Fixture f(version, nested);
    DWORD64 image = 0;
    auto function = RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(f.at(f.child.BeginAddress)), &image, nullptr);
    require(function && image == reinterpret_cast<DWORD64>(f.module) && !std::memcmp(function, &f.child, sizeof(f.child)),
        "OS did not select actual mapped PE child row");
    for (size_t probe : nested ? std::vector<size_t>{0} : std::vector<size_t>{0,5}) {
        NativeUnwind::SourceSnapshot snapshot;
        success(f.snapshot(snapshot, probe));
        auto source = snapshot.source();
        require(source.chain.size() == (nested ? 2u : 1u) && source.chain.front().unwindRva == (nested ? f.middle.UnwindData : f.primary.UnwindData)
            && source.chain.back().unwindRva == f.primary.UnwindData, "Mapped parents were not immediate-parent-first");
        auto moved = std::move(snapshot);
        source = moved.source();
        auto displaced = static_cast<unsigned char*>(VirtualAlloc(nullptr, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        require(displaced, "Cannot allocate unwind test output");
        InstructionDecoder::Relocation relocation;
        require(InstructionDecoder::relocate(displaced, InstructionDecoder::MAX_RELOCATED_BYTES, f.at(f.child.BeginAddress) + probe,
            f.child.EndAddress - f.child.BeginAddress - probe, relocation), "Cannot relocate mapped child instruction");
        NativeUnwind::Recipe recipe;
        success(NativeUnwind::derive(source, relocation, recipe));
        require(recipe.sourceVersion == version && relocation.sourceBytes == 5, "Mapped child interpretation changed");
        displaced[5] = 0x90; displaced[6] = 0x90;
        std::memcpy(displaced + 4096, recipe.before.data(), recipe.before.size());
        std::memcpy(displaced + 4224, recipe.after.data(), recipe.after.size());
        RUNTIME_FUNCTION rows[]{{0,5,4096},{5,7,4224}};
        require(RtlAddFunctionTable(rows, 2, reinterpret_cast<DWORD64>(displaced)), "Cannot register derived mapped child rows");
        for (bool post : {false,true}) {
            constexpr DWORD64 caller = 0x12345678, rbx = 0x1122334455667788, rsi = 0x8877665544332211,
                rdi = 0x2468246824682468, poison = 0xbad0bad0bad0bad0;
            std::array<DWORD64,128> stack{};
            auto returnAddress = stack.data() + 64; *returnAddress = caller;
            returnAddress[-1] = rbx; returnAddress[-5] = rsi; returnAddress[-4] = rdi;
            CONTEXT context{};
            context.Rip = reinterpret_cast<DWORD64>(f.at(f.child.BeginAddress)) + probe + (post ? 5 : 0);
            context.Rsp = reinterpret_cast<DWORD64>(returnAddress) - 72;
            context.Rbx = poison; context.Rsi = nested || probe || post ? poison : rsi;
            context.Rdi = nested ? (post ? poison : rdi) : (probe && post ? poison : rdi);
            DWORD64 originalFrame = 0, copiedFrame = 0;
            auto original = unwind(context, image, function, originalFrame);
            context.Rip = reinterpret_cast<DWORD64>(displaced) + (post ? 5 : 0);
            DWORD64 derivedBase = 0;
            auto derived = RtlLookupFunctionEntry(context.Rip, &derivedBase, nullptr);
            require(derived && derivedBase == reinterpret_cast<DWORD64>(displaced), "Derived function table lookup failed");
            auto copied = unwind(context, derivedBase, derived, copiedFrame);
            require(original.Rip == caller && original.Rsp == reinterpret_cast<DWORD64>(returnAddress + 1)
                && original.Rbx == rbx && original.Rsi == rsi && original.Rdi == rdi, "Mapped PE OS unwind did not restore caller");
            require(copied.Rip == original.Rip && copied.Rsp == original.Rsp && copied.Rbx == original.Rbx
                && copied.Rsi == original.Rsi && copied.Rdi == original.Rdi && copiedFrame == originalFrame,
                "Mapped source derived unwind disagreed with OS");
            ++checked;
        }
        require(RtlDeleteFunctionTable(rows) && VirtualFree(displaced, 0, MEM_RELEASE), "Cannot release unwind test output");
    }
}
void eligibility() {
    for (auto [offset, value, expected] : {
            std::tuple<ULONG,unsigned char,const char*>{5,0x7a,"unsupported-unwind-operation"},
            {3,0x25,"missing-frame-operation"}}) {
        Fixture f;
        f.put(f.primary.UnwindData + offset, value);
        NativeUnwind::SourceSnapshot snapshot;
        success(f.snapshot(snapshot));
        NativeUnwind::Recipe recipe{{0xaa},{0xbb},99};
        rejected(NativeUnwind::derive(snapshot.source(), {5,5,nullptr}, recipe), expected);
        require(recipe.before == std::vector<unsigned char>{0xaa} && recipe.after == std::vector<unsigned char>{0xbb}
            && recipe.sourceVersion == 99, "Mapped parent eligibility failure changed recipe");
    }
    {
        Fixture f;
        unsigned char zero = 0;
        f.put(f.child.UnwindData + 1, zero);
        f.put(f.child.UnwindData + 2, zero);
        f.put(f.child.UnwindData + 4, f.middle);
        NativeUnwind::SourceSnapshot snapshot;
        success(f.snapshot(snapshot));
        NativeUnwind::Recipe recipe;
        rejected(NativeUnwind::derive(snapshot.source(), {5,5,nullptr}, recipe), "chained-body-state-needs-proof");
    }
}
void stableSnapshots() {
    Fixture f;
    NativeUnwind::SourceSnapshot snapshot;
    success(f.snapshot(snapshot));
    auto source = snapshot.source();
    auto original = std::vector<unsigned char>(source.chain[0].code.begin(), source.chain[0].code.end());
    unsigned char changed = 0xcc;
    f.put(f.middle.BeginAddress, changed);
    f.put(f.middle.UnwindData, changed);
    f.unload();
    auto moved = std::move(snapshot);
    source = moved.source();
    require(std::equal(source.chain[0].code.begin(), source.chain[0].code.end(), original.begin())
        && source.chain[0].unwind[0] == 33, "Moved mapped snapshots borrowed live PE memory");
    NativeUnwind::Recipe recipe;
    success(NativeUnwind::derive(source, {5,5,nullptr}, recipe));
}
}
int main() {
    for (unsigned version : {1u,2u}) for (bool nested : {false,true}) nativeContexts(version,nested);
    stableSnapshots();
    negatives();
    eligibility();
    std::printf("MAPPED_NATIVE_UNWIND_PASS contexts=%u rejected=%u stableSnapshots=1 versions=1,2 leasedPE=1\n", checked, rejections);
}
