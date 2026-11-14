/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsJava.h"
#include "windowsJavaUnwind.h"
#include "windowsProfiler.h"
#include "windowsMutex.h"
#include "windowsSeh.h"
#include "arguments.h"
#include "writer.h"
#include "vmStructs.h"
#include "frameName.h"
#include "dictionary.h"
#include "profiler.h"
#include <jvmticmlr.h>
#include <algorithm>
#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>

void Profiler::snapshotRuntimeStubs(std::vector<CodeBlob>& result) {
    std::lock_guard lock(_stubs_lock);
    _runtime_stubs.snapshot(result);
}

namespace WindowsProfiler {
unsigned lookupJavaClass(Dictionary* classes, std::string_view value, bool descriptor) {
    if (descriptor && value.front() == 'L') { value.remove_prefix(1); value.remove_suffix(1); }
    if (std::none_of(value.begin(), value.end(), [](unsigned char byte) { return byte >= 0x80; })) {
        return classes->lookup(value.data(), value.size());
    }
    auto name = modifiedUtf8(value);
    return classes->lookup(name.empty() ? "[invalid_java_utf8]" : name.c_str());
}
}

namespace WindowsProfiler::Java {
namespace {
constexpr std::uintptr_t METHOD_TAG = std::uintptr_t{1} << 63;
struct Location { std::uintptr_t pc; std::vector<ASGCT_CallFrame> frames; };
struct Version {
    std::uintptr_t begin, end;
    jmethodID original;
    std::uint64_t from, to = UINT64_MAX;
    std::vector<Location> locations;
};
struct Interpreted {
    jmethodID original, snapshot;
    std::uint64_t from, to = UINT64_MAX;
    size_t lifetime = SIZE_MAX;
};
struct Bytecode {
    std::uintptr_t end;
    jmethodID snapshot;
    std::uint64_t from;
    size_t lifetime;
};
struct ChangeInterval { std::uint64_t from, to; };
WindowsMutex mutex;
std::map<std::uintptr_t, std::vector<std::unique_ptr<Version>>> versions;
std::map<std::uintptr_t, std::vector<Interpreted>> interpreted;
std::map<std::uintptr_t, std::vector<Bytecode>> bytecodes;
std::map<std::string, std::unique_ptr<Method>> methods;
std::vector<ChangeInterval> changes;
// A JVM operation can span recording stop/reset; preserve its nesting count.
unsigned activeChanges = 0;
std::uint64_t classChanges = 0, uncertainPcs = 0;
// Failed class snapshots invalidate address-reuse assumptions until reset.
std::atomic<bool> unsafeMapping{false};
std::atomic<std::uint64_t> generation{0}, readers{0}, loads{0}, unloads{0}, decoded{0}, failed{0};
std::atomic<std::uint64_t> unmapped{0};
std::atomic<std::uint64_t> preparedClasses{0}, missingMethodIds{0}, interpretedDecoded{0};
std::atomic<std::uint64_t> filteredMethodIds{0};
std::atomic<std::uint64_t> excludedMethodIds{0};
std::string missingClass;
std::atomic<bool> running{false};
std::uintptr_t maximumSize = 0;
std::uintptr_t maximumBytecodeSize = 0;
bool baselineLoads = false, generating = false;

std::uint64_t now() { LARGE_INTEGER value; QueryPerformanceCounter(&value); return value.QuadPart; }
struct Reader {
    std::uint64_t epoch = generation.load(std::memory_order_acquire);
    bool active = false;
    Reader() {
        if (!(epoch & 1)) return;
        readers.fetch_add(1, std::memory_order_acq_rel);
        active = generation.load(std::memory_order_acquire) == epoch;
    }
    ~Reader() { if (epoch & 1) readers.fetch_sub(1, std::memory_order_release); }
    bool current() const { return active && generation.load(std::memory_order_acquire) == epoch; }
};
struct Strings {
    jvmtiEnv* ti;
    char *name = nullptr, *signature = nullptr, *klass = nullptr;
    jclass type = nullptr;
    jvmtiLineNumberEntry* lines = nullptr;
    ~Strings() {
        if (type) VM::jni()->DeleteLocalRef(type);
        for (auto value : {name, signature, klass}) if (value) ti->Deallocate(reinterpret_cast<unsigned char*>(value));
        if (lines) ti->Deallocate(reinterpret_cast<unsigned char*>(lines));
    }
};
std::string utf8(const char* text) {
    auto result = WindowsProfiler::modifiedUtf8(text);
    if (*text && result.empty()) throw std::runtime_error("Invalid JVMTI modified UTF-8");
    return result;
}
jmethodID capture(jvmtiEnv* ti, jmethodID method, jclass expected = nullptr) {
    Strings data{ti};
    if (ti->GetMethodName(method, &data.name, &data.signature, nullptr) != JVMTI_ERROR_NONE
            || ti->GetMethodDeclaringClass(method, &data.type) != JVMTI_ERROR_NONE
            || ti->GetClassSignature(data.type, &data.klass, nullptr) != JVMTI_ERROR_NONE) {
        throw std::runtime_error("Cannot snapshot Java method");
    }
    if (expected && !VM::jni()->IsSameObject(expected, data.type)) throw std::runtime_error("Java method changed its declaring class during metadata capture");
    auto snapshot = std::make_unique<Method>();
    auto klass = utf8(data.klass);
    if (klass.size() < 2 || klass.front() != 'L' || klass.back() != ';') throw std::runtime_error("Invalid declaring class signature");
    snapshot->klass = klass.substr(1, klass.size() - 2);
    snapshot->name = utf8(data.name); snapshot->signature = utf8(data.signature);
    ti->GetMethodModifiers(method, &snapshot->modifiers);
    jint count = 0;
    if (ti->GetLineNumberTable(method, &count, &data.lines) == JVMTI_ERROR_NONE && count > 0) {
        snapshot->lines.assign(data.lines, data.lines + count);
    }
    std::string key;
    auto append = [&](const std::string& value) {
        std::uint64_t length = value.size();
        key.append(reinterpret_cast<const char*>(&length), sizeof(length)).append(value);
    };
    append(snapshot->klass); append(snapshot->name); append(snapshot->signature);
    key.append(reinterpret_cast<const char*>(&snapshot->modifiers), sizeof(snapshot->modifiers));
    for (const auto& line : snapshot->lines) {
        key.append(reinterpret_cast<const char*>(&line.start_location), sizeof(line.start_location));
        key.append(reinterpret_cast<const char*>(&line.line_number), sizeof(line.line_number));
    }
    auto [entry, inserted] = methods.try_emplace(std::move(key), nullptr);
    if (inserted) entry->second = std::move(snapshot);
    return reinterpret_cast<jmethodID>(reinterpret_cast<std::uintptr_t>(entry->second.get()) | METHOD_TAG);
}

struct MethodProbe { int count; VMMethod* method; jmethodID id; const char* bytecode; bool filtered = false; };
bool probe(VMKlass* klass, int index, MethodProbe& result) {
    __try {
        return guarded([&] {
            result.count = klass->methodCount();
            if (index < 0) return true;
            if (index >= result.count) return false;
            result.method = klass->methodAt(index);
            auto raw = result.method->id();
            result.id = result.method->validatedId();
            result.filtered = raw && !result.id;
            result.bytecode = result.method->bytecode();
            return result.id != nullptr;
        });
    } __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
}
}

const Method* metadata(jmethodID id) {
    auto value = reinterpret_cast<std::uintptr_t>(id);
    return value & METHOD_TAG ? reinterpret_cast<const Method*>(value & ~METHOD_TAG) : nullptr;
}

void reset() {
    std::lock_guard lock(mutex);
    versions.clear(); interpreted.clear(); bytecodes.clear(); maximumSize = 0; maximumBytecodeSize = 0;
    for (const auto& entry : methods) {
        auto id = reinterpret_cast<jmethodID>(reinterpret_cast<std::uintptr_t>(entry.second.get()) | METHOD_TAG);
        FrameName::forgetMethod(id);
    }
    methods.clear();
    changes.clear(); classChanges = 0; uncertainPcs = 0; unsafeMapping = false;
    loads = 0; unloads = 0; decoded = 0; failed = 0; unmapped = 0;
    preparedClasses = 0; missingMethodIds = 0; interpretedDecoded = 0;
    filteredMethodIds = 0; excludedMethodIds = 0; missingClass.clear();
}

void prepared(jvmtiEnv* ti, JNIEnv* env, jclass type) {
    Reader reader;
    if (!reader.active) return;
    try {
        jint status = 0;
        if (ti->GetClassStatus(type, &status) != JVMTI_ERROR_NONE || !(status & JVMTI_CLASS_STATUS_PREPARED)
                || (status & (JVMTI_CLASS_STATUS_ARRAY | JVMTI_CLASS_STATUS_PRIMITIVE))) return;
        std::lock_guard lock(mutex);
        if (!reader.current()) return;
        auto klass = VMKlass::fromJavaClass(env, type);
        MethodProbe first{};
        if (!probe(klass, -1, first)) throw std::runtime_error("Cannot read prepared Java methods");
        auto time = now();
        int missing = 0;
        for (int index = 0; index < first.count; ++index) {
            MethodProbe before{}, after{};
            bool available = probe(klass, index, before);
            if (!available) {
                missingMethodIds.fetch_add(1);
                missing++;
                if (before.filtered) filteredMethodIds.fetch_add(1);
                if (missingClass.empty()) {
                    Strings strings{ti};
                    if (ti->GetClassSignature(type, &strings.klass, nullptr) == JVMTI_ERROR_NONE) missingClass = utf8(strings.klass);
                }
                continue;
            }
            auto snapshot = capture(ti, before.id, type);
            int size = 0;
            if (!(metadata(snapshot)->modifiers & 0x500)) {
                jlocation start, end;
                if (ti->GetMethodLocation(before.id, &start, &end) != JVMTI_ERROR_NONE || start != 0 || end < 0 || end >= 65536) {
                    throw std::runtime_error("Cannot read Java bytecode range");
                }
                size = static_cast<int>(end + 1);
            }
            if (!probe(klass, index, after) || before.method != after.method || before.id != after.id || before.bytecode != after.bytecode) {
                missingMethodIds.fetch_add(1); continue;
            }
            auto address = reinterpret_cast<std::uintptr_t>(before.method);
            auto registration = JavaUnwind::metadata(before.method, before.bytecode, size, false);
            auto& history = interpreted[address];
            if (history.empty() || history.back().original != before.id || history.back().snapshot != snapshot || history.back().lifetime != registration.methodLife) {
                if (!history.empty()) history.back().to = time;
                history.push_back({before.id, snapshot, time, UINT64_MAX, registration.methodLife});
            }
            if (size) {
                auto begin = reinterpret_cast<std::uintptr_t>(before.bytecode);
                auto& code = bytecodes[begin];
                if (code.empty() || code.back().snapshot != snapshot || code.back().end != begin + size || code.back().lifetime != registration.bytecodeLife) {
                    code.push_back({begin + size, snapshot, time, registration.bytecodeLife});
                }
                maximumBytecodeSize = std::max(maximumBytecodeSize, static_cast<std::uintptr_t>(size));
            }
        }
        if (missing) {
            jint visible = 0;
            jmethodID* ids = nullptr;
            if (ti->GetClassMethods(type, &visible, &ids) == JVMTI_ERROR_NONE) {
                // HotSpot GetClassMethods deliberately omits VM overpass methods.
                if (first.count - visible == missing) excludedMethodIds.fetch_add(missing);
                ti->Deallocate(reinterpret_cast<unsigned char*>(ids));
            }
        }
        if (!generating && !JavaUnwind::publish()) failed.fetch_add(1);
        preparedClasses.fetch_add(1);
    } catch (...) { failed.fetch_add(1); unsafeMapping = true; }
}

void beginClassChange() noexcept {
    try {
        std::lock_guard lock(mutex);
        ++activeChanges;
        if (running.load()) {
            ++classChanges;
            if (activeChanges == 1) changes.push_back({now(), UINT64_MAX});
        }
    } catch (...) { failed.fetch_add(1); unsafeMapping = true; }
}

void endClassChange() noexcept {
    std::lock_guard lock(mutex);
    if (--activeChanges == 0 && running.load() && !unsafeMapping.load()) changes.back().to = now();
}

void generated(const void* code, int size, const char* name) {
    Reader reader;
    if (!reader.active) return;
    try {
        std::lock_guard lock(mutex);
        if (reader.current()) JavaUnwind::generated(code, size, name, !generating);
    } catch (...) { failed.fetch_add(1); }
}

void loaded(jvmtiEnv* ti, jmethodID method, jint size, const void* code, jint count,
            const jvmtiAddrLocationMap* locations, const void* info) {
    Reader reader;
    if (!reader.active) return;
    try {
        std::lock_guard lock(mutex);
        if (!reader.current()) return;
        auto begin = reinterpret_cast<std::uintptr_t>(code);
        if (size <= 0 || begin + size < begin) throw std::runtime_error("Invalid compiled method range");
        auto& history = versions[begin];
        for (const auto& version : history) if (version->to == UINT64_MAX && version->original == method && version->end == begin + size) return;
        auto version = std::make_unique<Version>();
        version->begin = begin; version->end = begin + size; version->original = method; version->from = 0;
        if (!generating) {
            auto lower = begin > maximumSize ? begin - maximumSize : 0;
            for (auto previous = versions.lower_bound(lower); previous != versions.end() && previous->first < version->end; ++previous) {
                for (const auto& old : previous->second) if (old->end > begin) {
                    if (old->to == UINT64_MAX) throw std::runtime_error("Overlapping active compiled methods");
                    version->from = std::max(version->from, old->to);
                }
            }
        }
        auto primary = capture(ti, method);
        auto type = FRAME_JIT_COMPILED;
        if (VMStructs::hasStackStructs()) {
            auto nm = CodeHeap::findNMethod(code);
            if (nm && nm->isNMethod()) {
                auto level = nm->level();
                if (level >= 1 && level <= 3) type = FRAME_C1_COMPILED;
            }
        }
        for (int i = 0; i < count; ++i) {
            auto pc = reinterpret_cast<std::uintptr_t>(locations[i].start_address);
            if (pc >= begin && pc < version->end) version->locations.push_back({pc, {{FrameType::encode(type, static_cast<int>(locations[i].location)), 0, primary}}});
        }
        for (auto header = VM::hotspot_version() > 0 ? static_cast<const jvmtiCompiledMethodLoadRecordHeader*>(info) : nullptr; header; header = header->next) {
            if (header->kind != JVMTI_CMLR_INLINE_INFO || header->majorinfoversion != JVMTI_CMLR_MAJOR_VERSION_1) continue;
            auto inlineInfo = reinterpret_cast<const jvmtiCompiledMethodLoadInlineRecord*>(header);
            if (inlineInfo->numpcs <= 0) continue;
            version->locations.clear();
            std::map<jmethodID, jmethodID> captured{{method, primary}};
            for (int i = 0; i < inlineInfo->numpcs; ++i) {
                const auto& point = inlineInfo->pcinfo[i];
                auto pc = reinterpret_cast<std::uintptr_t>(point.pc);
                if (pc < begin || pc >= version->end || point.numstackframes <= 0) continue;
                Location location{pc, {}};
                for (int frame = 0; frame < point.numstackframes; ++frame) {
                    auto id = point.methods[frame];
                    auto [entry, inserted] = captured.try_emplace(id, nullptr);
                    if (inserted) entry->second = capture(ti, id);
                    auto frameType = frame + 1 == point.numstackframes ? type : FRAME_INLINED;
                    location.frames.push_back({FrameType::encode(frameType, point.bcis[frame]), 0, entry->second});
                }
                version->locations.push_back(std::move(location));
            }
            break;
        }
        if (version->locations.empty()) version->locations.push_back({begin, {{FrameType::encode(type, 0), 0, primary}}});
        std::sort(version->locations.begin(), version->locations.end(), [](const Location& a, const Location& b) { return a.pc < b.pc; });
        maximumSize = std::max(maximumSize, static_cast<std::uintptr_t>(size));
        history.push_back(std::move(version)); loads.fetch_add(1);
        if (auto nm = VMStructs::hasStackStructs() ? CodeHeap::findNMethod(code) : nullptr) {
            JavaUnwind::compiled(code, size, nm, !generating);
        }
    } catch (...) { failed.fetch_add(1); }
}

void unloaded(jmethodID method, const void* code) {
    Reader reader;
    if (!reader.active) return;
    std::lock_guard lock(mutex);
    if (!reader.current()) return;
    if (auto found = versions.find(reinterpret_cast<std::uintptr_t>(code)); found != versions.end()) {
        auto time = now();
        for (auto& version : found->second) if (version->original == method && version->to == UINT64_MAX) version->to = time;
        unloads.fetch_add(1);
        JavaUnwind::unloaded(code, !generating,time);
    }
}

Error start() {
    if (!VM::loaded()) return Error::OK;
    auto unwindError = JavaUnwind::start();
    if (unwindError) return unwindError;
    {
        std::lock_guard lock(mutex);
        versions.clear(); interpreted.clear(); bytecodes.clear(); maximumSize = 0; maximumBytecodeSize = 0; generating = true;
        loads = 0; unloads = 0; decoded = 0; failed = 0; unmapped = 0;
        preparedClasses = 0; missingMethodIds = 0; interpretedDecoded = 0;
        filteredMethodIds = 0; excludedMethodIds = 0; missingClass.clear();
        changes.clear(); classChanges = 0; uncertainPcs = 0; unsafeMapping = false;
        if (activeChanges) changes.push_back({now(), UINT64_MAX});
        generation.fetch_add(1, std::memory_order_acq_rel);
        running = true;
    }
    baselineLoads = VM::hotspot_version() == 0 || !CodeHeap::available();
    auto ti = VM::jvmti();
    if (!VM::visitLoadedClasses(ti, VM::jni(), prepared)) {
        stop(); return Error("Cannot snapshot loaded Java classes");
    }
    try {
        std::vector<CodeBlob> stubs;
        Profiler::instance()->snapshotRuntimeStubs(stubs);
        std::sort(stubs.begin(), stubs.end(), [](const CodeBlob& a, const CodeBlob& b) {
            return static_cast<const char*>(a._end) - static_cast<const char*>(a._start)
                 < static_cast<const char*>(b._end) - static_cast<const char*>(b._start);
        });
        for (const auto& stub : stubs) generated(stub._start,
            static_cast<int>(static_cast<const char*>(stub._end) - static_cast<const char*>(stub._start)), stub._name);
    } catch (...) { failed.fetch_add(1); }
    if (ti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_COMPILED_METHOD_UNLOAD, nullptr) != JVMTI_ERROR_NONE
            || ti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_COMPILED_METHOD_LOAD, nullptr) != JVMTI_ERROR_NONE
            || ti->GenerateEvents(JVMTI_EVENT_COMPILED_METHOD_LOAD) != JVMTI_ERROR_NONE) {
        stop(); return Error("Cannot enable Windows Java compilation tracking");
    }
    { std::lock_guard lock(mutex); if (!JavaUnwind::publish()) failed.fetch_add(1); generating = false; }
    if (failed.load()) {
        auto message = JavaUnwind::firstError();
        stop();
        return Error(message ? message : "Cannot snapshot Windows Java metadata");
    }
    return Error::OK;
}
void stop() {
    if (!running.exchange(false)) return;
    generation.fetch_add(1, std::memory_order_acq_rel);
    VM::jvmti()->SetEventNotificationMode(JVMTI_DISABLE, JVMTI_EVENT_COMPILED_METHOD_UNLOAD, nullptr);
    if (!baselineLoads) VM::jvmti()->SetEventNotificationMode(JVMTI_DISABLE, JVMTI_EVENT_COMPILED_METHOD_LOAD, nullptr);
    while (readers.load(std::memory_order_acquire)) SwitchToThread();
    JavaUnwind::stop();
}

int decode(std::uint64_t pc, std::uint64_t timestamp, ASGCT_CallFrame* frames, int capacity, bool& truncated, bool generated, bool* bytecode) {
    std::lock_guard lock(mutex);
    auto change = std::upper_bound(changes.begin(), changes.end(), timestamp,
        [](std::uint64_t time, const ChangeInterval& interval) { return time < interval.from; });
    if (unsafeMapping.load() || (change != changes.begin() && timestamp < (change - 1)->to)) {
        ++uncertainPcs;
        return 0;
    }
    jmethodID selected = nullptr;
    std::uint64_t latest = 0;
    size_t lifetime = SIZE_MAX;
    int bci = 0;
    bool isBytecode = false;
    if (auto found = interpreted.find(pc); found != interpreted.end()) {
        for (auto version = found->second.rbegin(); version != found->second.rend(); ++version) {
            if (timestamp >= version->from && timestamp < version->to) {
                selected = version->snapshot; latest = version->from; lifetime = version->lifetime;
                break;
            }
        }
    }
    auto lowerCode = pc > maximumBytecodeSize ? pc - maximumBytecodeSize : 0;
    for (auto entry = bytecodes.lower_bound(lowerCode); entry != bytecodes.end() && entry->first <= pc; ++entry) {
        for (const auto& version : entry->second) if (pc < version.end && timestamp >= version.from && (!selected || version.from >= latest)) {
            selected = version.snapshot; latest = version.from; lifetime = version.lifetime;
            bci = static_cast<int>(pc - entry->first); isBytecode = true;
        }
    }
    if (selected && JavaUnwind::metadataAlive(lifetime, timestamp)) {
        if (!capacity) { truncated = true; return 0; }
        frames[0] = {FrameType::encode(FRAME_INTERPRETED, bci), 0, selected};
        if (bytecode) *bytecode = isBytecode;
        decoded.fetch_add(1); interpretedDecoded.fetch_add(1);
        return 1;
    }
    if (!generated) return 0;
    auto lower = pc > maximumSize ? pc - maximumSize : 0;
    for (auto entry = versions.lower_bound(lower); entry != versions.end() && entry->first <= pc; ++entry) {
        for (const auto& version : entry->second) {
            if (pc >= version->end || timestamp < version->from || timestamp >= version->to) continue;
            auto found = std::upper_bound(version->locations.begin(), version->locations.end(), pc,
                [](std::uintptr_t pc, const Location& location) { return pc < location.pc; });
            if (found != version->locations.begin()) --found;
            int count = std::min<int>(capacity, found->frames.size());
            truncated |= static_cast<size_t>(count) != found->frames.size();
            std::copy_n(found->frames.begin(), count, frames);
            decoded.fetch_add(1);
            return count;
        }
    }
    unmapped.fetch_add(1);
    return 0;
}
void writeMetrics(Writer& out) {
    JavaUnwind::writeMetrics(out);
    out << "windows_java_compilations " << u64(loads.load()) << '\n';
    out << "windows_java_unloads " << u64(unloads.load()) << '\n';
    out << "windows_java_decoded " << u64(decoded.load()) << '\n';
    out << "windows_java_metadata_failed " << u64(failed.load()) << '\n';
    out << "windows_java_unmapped_vm_pcs " << u64(unmapped.load()) << '\n';
    out << "windows_java_prepared_classes " << u64(preparedClasses.load()) << '\n';
    out << "windows_java_missing_method_ids " << u64(missingMethodIds.load()) << '\n';
    out << "windows_java_filtered_method_ids " << u64(filteredMethodIds.load()) << '\n';
    out << "windows_java_excluded_method_ids " << u64(excludedMethodIds.load()) << '\n';
    out << "windows_java_interpreted_decoded " << u64(interpretedDecoded.load()) << '\n';
    std::lock_guard lock(mutex);
    out << "windows_java_class_changes " << u64(classChanges) << '\n';
    out << "windows_java_active_class_changes " << u64(activeChanges) << '\n';
    out << "windows_java_transition_pcs " << u64(uncertainPcs) << '\n';
    out << "windows_java_mapping_unsafe " << u64(unsafeMapping.load()) << '\n';
    if (!missingClass.empty()) out << "windows_java_missing_method_first_class " << missingClass.c_str() << '\n';
    u64 bytes = 0;
    for (const auto& entry : methods) bytes += sizeof(Method) + entry.first.size()
        + entry.second->klass.size() + entry.second->name.size() + entry.second->signature.size()
        + entry.second->lines.size() * sizeof(jvmtiLineNumberEntry);
    out << "windows_java_methods " << u64(methods.size()) << '\n';
    out << "windows_java_method_bytes " << bytes << '\n';
}
}
