/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "asprof.h"
#include <bcrypt.h>
#include <cstdio>
#include <cstring>
#include <map>

namespace Asprof {
namespace {
std::wstring executableDirectory() {
    std::wstring path(32768, L'\0');
    path.resize(GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size())));
    return path.substr(0, path.find_last_of(L'\\') + 1);
}

std::string readFile(const std::wstring& path) {
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
    LARGE_INTEGER size;
    if (!file || !GetFileSizeEx(file.value, &size)) fail("Cannot read " + utf8(path) + ": " + windowsError(GetLastError()));
    std::string data(static_cast<size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    if (!ReadFile(file.value, data.data(), static_cast<DWORD>(data.size()), &read, nullptr) || read != data.size()) {
        fail("Cannot read " + utf8(path) + ": " + windowsError(GetLastError()));
    }
    return data;
}

// The agent property of a launcher-directory profiler.properties file (java.util.Properties syntax
// without escapes; paths use forward slashes).
std::optional<std::string> agentProperty(const std::wstring& path) {
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) return {};
    auto data = readFile(path);
    std::optional<std::string> agent;
    for (size_t start = 0; start < data.size();) {
        auto end = data.find_first_of("\r\n", start);
        if (end == std::string::npos) end = data.size();
        auto line = data.substr(start, end - start);
        start = end + 1;
        auto first = line.find_first_not_of(" \t\f");
        if (first == std::string::npos || line[first] == '#' || line[first] == '!') continue;
        if (line.find('\\') != std::string::npos) fail(utf8(path) + ": use forward slashes; escapes are not supported");
        auto separator = line.find_first_of("=: \t\f", first);
        auto key = line.substr(first, separator == std::string::npos ? std::string::npos : separator - first);
        std::string value;
        if (separator != std::string::npos) {
            auto at = line.find_first_not_of(" \t\f", separator);
            if (at != std::string::npos && (line[at] == '=' || line[at] == ':')) at = line.find_first_not_of(" \t\f", at + 1);
            if (at != std::string::npos) value = line.substr(at);
        }
        if (key == "agent") agent = value;
    }
    return agent;
}

struct PeFile {
    struct Export { DWORD ordinal; std::optional<std::string> name; DWORD rva; std::optional<std::string> forwarder; };
    std::string data;
    std::string machine;
    std::vector<Export> exports;
    std::vector<std::string> imports;
    std::vector<IMAGE_SECTION_HEADER> sections;
    DWORD headerSize = 0;

    template<class T> T at(size_t offset) const {
        if (offset + sizeof(T) > data.size()) fail("Truncated PE file");
        T value;
        std::memcpy(&value, data.data() + offset, sizeof(T));
        return value;
    }
    size_t offset(DWORD rva) const {
        if (rva < headerSize) return rva;
        for (const auto& s : sections) {
            if (rva >= s.VirtualAddress && rva - s.VirtualAddress < s.SizeOfRawData) return s.PointerToRawData + (rva - s.VirtualAddress);
        }
        char text[64];
        std::snprintf(text, sizeof(text), "PE RVA has no file data: 0x%lx", rva);
        fail(text);
    }
    std::string string(DWORD rva) const {
        auto start = offset(rva);
        auto end = data.find('\0', start);
        if (end == std::string::npos) fail("Truncated PE string");
        return data.substr(start, end - start);
    }

    explicit PeFile(const std::wstring& path) : data(readFile(path)) {
        auto name = utf8(path);
        if (at<WORD>(0) != IMAGE_DOS_SIGNATURE) fail("Not a PE library: " + name);
        auto pe = at<DWORD>(0x3c);
        if (at<DWORD>(pe) != IMAGE_NT_SIGNATURE) fail("Invalid PE signature: " + name);
        auto file = at<IMAGE_FILE_HEADER>(pe + 4);
        if (file.Machine == IMAGE_FILE_MACHINE_AMD64) machine = "amd64";
        else if (file.Machine == IMAGE_FILE_MACHINE_ARM64) machine = "aarch64";
        else fail("Only x64 and ARM64 PE libraries are supported: " + name);
        auto optional = pe + 24;
        if (at<WORD>(optional) != IMAGE_NT_OPTIONAL_HDR64_MAGIC) fail("Expected PE32+: " + name);
        auto header = at<IMAGE_OPTIONAL_HEADER64>(optional);
        headerSize = header.SizeOfHeaders;
        for (WORD i = 0; i < file.NumberOfSections; ++i) sections.push_back(at<IMAGE_SECTION_HEADER>(optional + file.SizeOfOptionalHeader + i * 40));
        if (header.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) readExports(header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
        if (header.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) readImports(header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    }

    void readExports(IMAGE_DATA_DIRECTORY directory) {
        if (!directory.VirtualAddress) return;
        auto table = at<IMAGE_EXPORT_DIRECTORY>(offset(directory.VirtualAddress));
        std::map<WORD, std::vector<std::string>> named;
        for (DWORD i = 0; i < table.NumberOfNames; ++i) {
            auto ordinal = at<WORD>(offset(table.AddressOfNameOrdinals) + i * 2);
            named[ordinal].push_back(string(at<DWORD>(offset(table.AddressOfNames) + i * 4)));
        }
        for (DWORD i = 0; i < table.NumberOfFunctions; ++i) {
            auto rva = at<DWORD>(offset(table.AddressOfFunctions) + i * 4);
            if (!rva) continue;
            std::optional<std::string> forwarder;
            if (rva >= directory.VirtualAddress && rva < directory.VirtualAddress + directory.Size) forwarder = string(rva);
            auto names = named.find(static_cast<WORD>(i));
            if (names == named.end()) exports.push_back({table.Base + i, {}, rva, forwarder});
            else for (const auto& n : names->second) exports.push_back({table.Base + i, n, rva, forwarder});
        }
    }

    void readImports(DWORD rva) {
        if (!rva) return;
        for (auto d = offset(rva); at<DWORD>(d) != 0 || at<DWORD>(d + 12) != 0; d += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
            imports.push_back(string(at<DWORD>(d + 12)));
        }
    }
};

std::string sha256(const std::string& data) {
    unsigned char digest[32];
    if (BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
                   static_cast<ULONG>(data.size()), digest, sizeof(digest)) != 0) fail("SHA-256 failed");
    std::string hex;
    char byte[3];
    for (auto b : digest) { std::snprintf(byte, sizeof(byte), "%02x", b); hex += byte; }
    return hex;
}

std::string quote(const std::optional<std::string>& value) {
    if (!value) return "null";
    std::string result = "\"";
    for (unsigned char c : *value) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (c < 32) { char escape[8]; std::snprintf(escape, sizeof(escape), "\\u%04x", c); result += escape; }
                else result += static_cast<char>(c);
        }
    }
    return result + '"';
}
}

std::wstring Library::helper() const {
    return dll.substr(0, dll.find_last_of(L'\\') + 1) + L"asprof-helper.exe";
}

// --libpath, then ASYNC_PROFILER_DLL, then profiler.properties beside asprof.exe, then the DLL beside it.
Library Library::resolve(const std::optional<std::string>& libpath) {
    auto home = executableDirectory();
    std::wstring dll;
    WCHAR environment[32768];
    auto length = GetEnvironmentVariableW(L"ASYNC_PROFILER_DLL", environment, 32768);
    std::wstring configured(environment, length < 32768 ? length : 0);
    if (libpath) {
        dll = wide(*libpath);
    } else if (configured.find_first_not_of(L" \t") != std::wstring::npos) {
        dll = configured;
    } else if (auto agent = agentProperty(home + L"profiler.properties")) {
        dll = wide(*agent);
        if (dll.size() < 2 || (dll[1] != L':' && dll[0] != L'/' && dll[0] != L'\\')) dll = home + dll;
    } else {
        dll = home + L"asyncProfiler.dll";
    }
    for (auto& c : dll) if (c == L'/') c = L'\\';
    dll = absolutePath(dll);
    if (GetFileAttributesW(dll.c_str()) == INVALID_FILE_ATTRIBUTES) fail("Profiler library not found: " + utf8(dll));
    PeFile pe(dll);
    if (pe.machine != "amd64") fail("This port requires a Windows x86-64 profiler DLL");
    for (auto symbol : {"Agent_OnAttach", "asprof_execute", "asprof_register_jfr_event"}) {
        bool found = false;
        for (const auto& e : pe.exports) found |= e.name == std::string(symbol) && !e.forwarder;
        if (!found) fail(std::string("Profiler DLL is missing ") + symbol + ": " + utf8(dll));
    }
    return {dll};
}

// The version in the "async-profiler VERSION" literal of the DLL's JFR recording metadata.
std::string embeddedVersion(const std::string& data) {
    const std::string marker = "async-profiler ";
    for (auto at = data.find(marker); at != std::string::npos; at = data.find(marker, at + 1)) {
        auto start = at + marker.size(), end = start;
        while (end < data.size() && data[end] >= ' ' && data[end] <= '~') ++end;
        if (end > start && data[start] >= '0' && data[start] <= '9') return data.substr(start, end - start);
    }
    return "unknown";
}

std::string Library::inspect() const {
    PeFile pe(dll);
    auto name = utf8(dll.substr(dll.find_last_of(L'\\') + 1));
    std::string result = "{\n  \"file\": " + quote(name) + ",\n  \"machine\": " + quote(pe.machine)
            + ",\n  \"version\": " + quote(embeddedVersion(pe.data)) + ",\n  \"sha256\": " + quote(sha256(pe.data))
            + ",\n  \"exports\": [";
    for (size_t i = 0; i < pe.exports.size(); ++i) {
        const auto& e = pe.exports[i];
        char rva[16];
        std::snprintf(rva, sizeof(rva), "0x%lx", e.rva);
        result += (i ? "," : "") + std::string("\n    {\"ordinal\": ") + std::to_string(e.ordinal) + ", \"name\": " + quote(e.name)
                + ", \"rva\": " + quote(std::string(rva)) + ", \"forwarder\": " + quote(e.forwarder) + "}";
    }
    result += "\n  ],\n  \"imports\": [";
    for (size_t i = 0; i < pe.imports.size(); ++i) result += (i ? ", " : "") + quote(pe.imports[i]);
    return result + "]\n}\n";
}
}
