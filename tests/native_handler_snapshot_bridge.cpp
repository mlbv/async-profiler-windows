/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef ASPROF_NATIVE_PREP_TEST_BRIDGE
#error This bridge belongs only to the private native preparation test artifact.
#endif
#include "platform.h"
#include "vmStructs.h"
#include "vmEntry.h"
#include "windowsCompiledHandlers.h"
#include "windowsLeafUnwind.h"
#include "native_handler_checkpoint.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <mutex>
#include <vector>
#include <map>
#include <utility>
#include <thread>
#include <atomic>
#include <cstdlib>
#include <algorithm>

namespace {
using Snapshot = WindowsProfiler::JavaUnwind::Compiled::Handlers::Snapshot;
struct MethodAccess : VMStructs {
    // JDK26 jmethodIDs are opaque; match the holder's own ID table instead.
    static VMMethod* resolve(JNIEnv* env,jclass holder,jmethodID id) {
        if (!hasClassMethods()) return nullptr;
        auto klass = VMKlass::fromJavaClass(env,holder);
        for (int index = 0, count = klass->methodCount(); index < count; ++index) {
            if (auto method = klass->methodAt(index); method->id() == id) return method;
        }
        return nullptr;
    }
};
// Raw JVMTI names of the same StubGenerator stubs across supported versions.
bool stubNamed(const char* name,const char* stub) {
    char expected[96];
    switch (VM::hotspot_version()) {
        case 26: std::snprintf(expected,sizeof(expected),"Stub Generator %s_stub",stub); break;
        case 27: std::snprintf(expected,sizeof(expected),"%s_stub (stub gen)",stub); break;
        default: std::snprintf(expected,sizeof(expected),"%s",stub);
    }
    return std::strcmp(name,expected) == 0;
}
struct Captured {
    std::string name, error;
    Snapshot snapshot;
    HandlerCheckpoint::CaptureStamp stamp;
    jmethodID id = nullptr;
    NMethod* nmethod = nullptr;
    int level = 0;
    bool conventionalFrame = false;
};
struct Observer {
    std::vector<Captured> methods;
    std::uintptr_t barrier = 0, stub = 0;
    std::size_t stubSize = 0, witnessBegin = 0;
    const char* error = nullptr;
    std::map<jmethodID,VMMethod*> implicitMethods;
    jclass retainedFixture = nullptr;
};
// JVMTI disposal leaves already-dispatched callbacks running. Admission must
// outlive every observer and close before its environment becomes invalid.
std::mutex callbackMutex;
std::map<jvmtiEnv*,Observer*> observers;
void publish(jvmtiEnv* ti,Observer& observer) {
    std::lock_guard lock(callbackMutex);
    observers.emplace(ti,&observer);
}
void retire(jvmtiEnv* ti) {
    std::lock_guard lock(callbackMutex);
    observers.erase(ti);
}
struct Admission {
    std::unique_lock<std::mutex> lock{callbackMutex};
    Observer* observer = nullptr;
    explicit Admission(jvmtiEnv* ti) {
        auto found = observers.find(ti);
        if (found != observers.end()) observer = found->second;
    }
};
struct Observation {
    Observer observer;
    jvmtiEnv* environment = nullptr;
    JNIEnv* ownerEnv = nullptr;
    void close() {
        if (auto ti = std::exchange(environment,nullptr)) {
            retire(ti);
            ti->DisposeEnvironment();
        }
        if (auto fixture = std::exchange(observer.retainedFixture,nullptr)) ownerEnv->DeleteGlobalRef(fixture);
    }
    ~Observation() { close(); }
};
void JNICALL generated(jvmtiEnv* ti, const char* name, const void* address, jint size) {
    Admission admission(ti);
    if (!admission.observer) return;
    auto& observer = *admission.observer;
    if (stubNamed(name,"call_stub") && size > 0) {
        observer.stub = reinterpret_cast<std::uintptr_t>(address);
        observer.stubSize = static_cast<std::size_t>(size);
    }
    if (std::strcmp(name, "nmethod_entry_barrier") != 0
            && !(VM::hotspot_version() >= 25 && VM::hotspot_version() <= 27 && stubNamed(name, "method_entry_barrier"))) return;
    observer.barrier = reinterpret_cast<std::uintptr_t>(address);
}
void JNICALL loaded(jvmtiEnv* ti, jmethodID method, jint size, const void* code, jint,
                    const jvmtiAddrLocationMap*, const void*) {
    Admission admission(ti);
    if (!admission.observer) return;
    auto& observer = *admission.observer;
    char* name = nullptr;
    jclass klass = nullptr;
    char* signature = nullptr;
    if (ti->GetMethodName(method, &name, nullptr, nullptr) != JVMTI_ERROR_NONE) {
        observer.error = "Cannot inspect compiled method name";
        return;
    }
    bool selected = std::strcmp(name, "plain") == 0 || std::strcmp(name, "throwing") == 0
        || std::strcmp(name, "scalar") == 0 || std::strcmp(name, "unprovenFmaTarget") == 0
        || std::strcmp(name, "faulting") == 0 || std::strcmp(name, "dividing") == 0
        || std::strcmp(name,"handlerTarget") == 0 || std::strcmp(name,"handlerCaller") == 0
        || std::strcmp(name,"handlerRoot") == 0;
    if (observer.implicitMethods.contains(method)
            || (selected && ti->GetMethodDeclaringClass(method, &klass) == JVMTI_ERROR_NONE
                && ti->GetClassSignature(klass, &signature, nullptr) == JVMTI_ERROR_NONE
                && ((std::strcmp(signature, "LCompiledHandlerSnapshotSmoke;") == 0
                        && std::strcmp(name, "unprovenFmaTarget") != 0)
                    || (std::strcmp(signature, "LEtwJavaSmoke;") == 0 && std::strcmp(name, "unprovenFmaTarget") == 0)))) {
        Captured captured;
        captured.name = name;
        captured.id = method;
        auto nm = CodeHeap::findNMethod(code);
        if (!nm) captured.error = "Missing callback nmethod";
        else {
            captured.nmethod = nm;
            captured.level = nm->level();
            auto implicit = observer.implicitMethods.find(method);
            if (implicit != observer.implicitMethods.end() && nm->method() != implicit->second)
                captured.error = "Callback nmethod differs from cached VM method";
            else if (auto error = nm->snapshotUnwindHandlers(code,size,captured.snapshot,
                    implicit == observer.implicitMethods.end() ? nullptr : &captured.stamp)) captured.error = error;
            else {
                const auto& snapshot = captured.snapshot;
                auto completeOffset = nm->frameCompleteOffset();
                auto complete = reinterpret_cast<std::uintptr_t>(nm->code()) + completeOffset;
                captured.conventionalFrame = !nm->isFrameless() && completeOffset >= 0 && complete >= snapshot.address()
                    && WindowsProfiler::JavaUnwind::Leaf::savedRbpSlot(snapshot.code().data(),snapshot.code().size(),
                        snapshot.entry(),complete - snapshot.address(),snapshot.allocation());
            }
        }
        observer.methods.push_back(std::move(captured));
    }
    if (signature) ti->Deallocate(reinterpret_cast<unsigned char*>(signature));
    // HotSpot's callback-local JNI handle block releases klass on return.
    ti->Deallocate(reinterpret_cast<unsigned char*>(name));
}
void certificateData(const char* which,const Captured& captured,const Snapshot& snapshot,int level,bool conventional,
        std::uintptr_t barrier) {
    char fields[384];
    std::snprintf(fields,sizeof(fields),
        "HANDLER_CERTIFICATE_DATA which=%s name=%s nmethod=%p id=%p level=%d conventional=%d address=%llx barrier=%llx entry=%zu allocation=%u bytes=",
        which,captured.name.c_str(),static_cast<void*>(captured.nmethod),reinterpret_cast<void*>(captured.id),
        level,conventional,static_cast<unsigned long long>(snapshot.address()),
        static_cast<unsigned long long>(barrier),snapshot.entry(),snapshot.allocation());
    std::string line = fields;
    constexpr char hex[] = "0123456789abcdef";
    for (auto byte : snapshot.code()) { line += hex[byte >> 4]; line += hex[byte & 15]; }
    line += " handlers=";
    if (snapshot.edges().empty()) line += "-";
    for (const auto& edge : snapshot.edges())
        line += std::to_string(edge.source) + ":" + std::to_string(edge.target) + ":" + (edge.callReturn ? "1," : "0,");
    line += " faults=";
    if (snapshot.faults().empty()) line += "-";
    for (const auto& edge : snapshot.faults())
        line += std::to_string(edge.source) + ":" + std::to_string(edge.target) + ",";
    std::fprintf(stderr,"%s\n",line.c_str());
}
bool checkpointSnapshot(void* data,std::uintptr_t pc,jmethodID id,Snapshot& snapshot,int& level,bool& conventional) {
    std::lock_guard lock(callbackMutex);
    auto& observer = *static_cast<Observer*>(data);
    auto nm = CodeHeap::findNMethod(reinterpret_cast<void*>(pc));
    if (!nm || !nm->isNMethod() || !nm->method() || nm->method()->id() != id) {
        const char* reason = !nm ? "missing-nmethod" : !nm->isNMethod() ? "not-nmethod"
            : !nm->method() ? "missing-method" : "method-id";
        std::fprintf(stderr,"HANDLER_CERTIFICATE_LOOKUP reason=%s pc=%llx expectedId=%p nmethod=%p actualId=%p\n",
            reason,static_cast<unsigned long long>(pc),reinterpret_cast<void*>(id),static_cast<void*>(nm),
            nm && nm->isNMethod() && nm->method() ? reinterpret_cast<void*>(nm->method()->id()) : nullptr);
        return false;
    }
    std::size_t idRecords = 0,nmethodRecords = 0,errorRecords = 0,rangeRecords = 0;
    for (auto index = observer.methods.size(); index > observer.witnessBegin;) {
        const auto& captured = observer.methods[--index];
        if (captured.id != id) continue;
        ++idRecords;
        if (captured.nmethod != nm) continue;
        ++nmethodRecords;
        if (!captured.error.empty()) {
            ++errorRecords;
            std::fprintf(stderr,"HANDLER_CERTIFICATE_LOOKUP reason=retained-parse-error name=%s nmethod=%p error=%s\n",
                captured.name.c_str(),static_cast<void*>(nm),captured.error.c_str());
            continue;
        }
        const auto& previous = captured.snapshot;
        if (pc < previous.address() || pc - previous.address() >= previous.code().size()) {
            ++rangeRecords;
            std::fprintf(stderr,"HANDLER_CERTIFICATE_LOOKUP reason=retained-range name=%s pc=%llx address=%llx size=%zu\n",
                captured.name.c_str(),static_cast<unsigned long long>(pc),
                static_cast<unsigned long long>(previous.address()),previous.code().size());
            continue;
        }
        Snapshot fresh;
        if (auto error = nm->snapshotUnwindHandlers(reinterpret_cast<void*>(previous.address()),
                static_cast<int>(previous.code().size()),fresh)) {
            std::fprintf(stderr,"HANDLER_CERTIFICATE_LOOKUP reason=fresh-parse-error name=%s nmethod=%p error=%s\n",
                captured.name.c_str(),static_cast<void*>(nm),error);
            certificateData("retained",captured,previous,captured.level,captured.conventionalFrame,observer.barrier);
            return false;
        }
        if (nm->level() != captured.level || fresh.address() != previous.address()
                || fresh.entry() != previous.entry() || fresh.allocation() != previous.allocation()
                || !std::equal(fresh.code().begin(),fresh.code().end(),previous.code().begin(),previous.code().end())
                || !std::equal(fresh.edges().begin(),fresh.edges().end(),previous.edges().begin(),previous.edges().end(),
                    [](const auto& a,const auto& b) {
                        return a.source == b.source && a.target == b.target && a.callReturn == b.callReturn;
                    })
                || !std::equal(fresh.faults().begin(),fresh.faults().end(),previous.faults().begin(),previous.faults().end(),
                    [](const auto& a,const auto& b) { return a.source == b.source && a.target == b.target; })) {
            auto difference = std::mismatch(fresh.code().begin(),fresh.code().end(),previous.code().begin(),previous.code().end());
            auto first = static_cast<std::size_t>(difference.first - fresh.code().begin());
            bool codeEqual = difference.first == fresh.code().end() && difference.second == previous.code().end();
            bool edgesEqual = std::equal(fresh.edges().begin(),fresh.edges().end(),previous.edges().begin(),previous.edges().end(),
                [](const auto& a,const auto& b) { return a.source == b.source && a.target == b.target && a.callReturn == b.callReturn; });
            bool faultsEqual = std::equal(fresh.faults().begin(),fresh.faults().end(),previous.faults().begin(),previous.faults().end(),
                [](const auto& a,const auto& b) { return a.source == b.source && a.target == b.target; });
            std::fprintf(stderr,
                "HANDLER_CERTIFICATE_LOOKUP reason=certificate-mismatch name=%s pc=%llx nmethod=%p id=%p levelEqual=%d addressEqual=%d entryEqual=%d allocationEqual=%d codeEqual=%d edgesEqual=%d faultsEqual=%d firstCodeDiff=%zu retainedByte=%d freshByte=%d\n",
                captured.name.c_str(),static_cast<unsigned long long>(pc),static_cast<void*>(nm),reinterpret_cast<void*>(id),
                nm->level() == captured.level,fresh.address() == previous.address(),fresh.entry() == previous.entry(),
                fresh.allocation() == previous.allocation(),codeEqual,edgesEqual,faultsEqual,first,
                difference.second == previous.code().end() ? -1 : *difference.second,
                difference.first == fresh.code().end() ? -1 : *difference.first);
            auto completeOffset = nm->frameCompleteOffset();
            auto complete = reinterpret_cast<std::uintptr_t>(nm->code()) + completeOffset;
            bool freshConventional = !nm->isFrameless() && completeOffset >= 0 && complete >= fresh.address()
                && WindowsProfiler::JavaUnwind::Leaf::savedRbpSlot(fresh.code().data(),fresh.code().size(),
                    fresh.entry(),complete - fresh.address(),fresh.allocation());
            certificateData("retained",captured,previous,captured.level,captured.conventionalFrame,observer.barrier);
            certificateData("fresh",captured,fresh,nm->level(),freshConventional,observer.barrier);
            return false;
        }
        snapshot = std::move(fresh);
        level = nm->level();
        auto completeOffset = nm->frameCompleteOffset();
        auto complete = reinterpret_cast<std::uintptr_t>(nm->code()) + completeOffset;
        conventional = !nm->isFrameless() && completeOffset >= 0 && complete >= snapshot.address()
            && WindowsProfiler::JavaUnwind::Leaf::savedRbpSlot(snapshot.code().data(),snapshot.code().size(),
                snapshot.entry(),complete - snapshot.address(),snapshot.allocation());
        if (conventional != captured.conventionalFrame) {
            std::fprintf(stderr,"HANDLER_CERTIFICATE_LOOKUP reason=route name=%s nmethod=%p retained=%d fresh=%d\n",
                captured.name.c_str(),static_cast<void*>(nm),captured.conventionalFrame,conventional);
            certificateData("retained",captured,previous,captured.level,captured.conventionalFrame,observer.barrier);
            certificateData("fresh",captured,snapshot,level,conventional,observer.barrier);
        }
        return conventional == captured.conventionalFrame;
    }
    std::fprintf(stderr,
        "HANDLER_CERTIFICATE_LOOKUP reason=retained-record-absent pc=%llx expectedId=%p nmethod=%p totalRecords=%zu witnessBegin=%zu idRecords=%zu nmethodRecords=%zu errorRecords=%zu rangeRecords=%zu\n",
        static_cast<unsigned long long>(pc),reinterpret_cast<void*>(id),static_cast<void*>(nm),observer.methods.size(),
        observer.witnessBegin,idRecords,nmethodRecords,errorRecords,rangeRecords);
    return false;
}
bool coldStampEqual(const HandlerCheckpoint::CaptureStamp& stamp,std::uintptr_t nmethod) {
    if (stamp.cells.empty() || stamp.bytes.empty()) return false;
    auto copy = [](std::uintptr_t address,void* output,std::size_t size) {
        SIZE_T copied = 0;
        return !size || (address && ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(address),
            output,size,&copied) && copied == size);
    };
    auto equal = [&](const auto& cell) {
        if ((cell.width != 1 && cell.width != 2 && cell.width != 4 && cell.width != 8)
                || (cell.address & (cell.width - 1))) return false;
        std::uint64_t actual = 0;
        return copy(cell.address,&actual,cell.width) && actual == cell.expected;
    };
    const auto& root = stamp.cells.back();
    if (root.width != sizeof(std::uintptr_t) || root.expected != nmethod || !equal(root)) return false;
    for (const auto& cell : stamp.cells) if (!equal(cell)) return false;
    for (const auto& range : stamp.bytes) {
        if (range.bytes.size() > 16 * 1024 * 1024) return false;
        std::vector<unsigned char> actual(range.bytes.size());
        if (!copy(range.address,actual.data(),actual.size()) || actual != range.bytes) return false;
    }
    return equal(root);
}
bool coldSnapshot(void* data,jmethodID id,HandlerCheckpoint::Certificate& result) {
    std::lock_guard lock(callbackMutex);
    auto& observer = *static_cast<Observer*>(data);
    if (!observer.implicitMethods.contains(id)) return false;
    for (auto index = observer.methods.size(); index > observer.witnessBegin;) {
        const auto& captured = observer.methods[--index];
        if (captured.id != id) continue;
        if (!captured.error.empty() || !coldStampEqual(captured.stamp,reinterpret_cast<std::uintptr_t>(captured.nmethod))) {
            std::fprintf(stderr,"IMPLICIT_COLD_CERTIFICATE_REJECTED name=%s level=%d error=%s stampCells=%zu stampBytes=%zu\n",
                captured.name.c_str(),captured.level,captured.error.c_str(),captured.stamp.cells.size(),captured.stamp.bytes.size());
            continue;
        }
        // Reading equality inputs is safe even if an old blob was retired.
        // Equality provides no lease; the VEH separately proves active frames.
        certificateData("implicit-cold",captured,captured.snapshot,captured.level,captured.conventionalFrame,observer.barrier);
        result = {captured.snapshot,captured.stamp,captured.level,captured.conventionalFrame};
        return true;
    }
    return false;
}
struct TestSignal {
    HANDLE event = CreateEventW(nullptr,TRUE,FALSE,nullptr);
    TestSignal() { if (!event) std::abort(); }
    ~TestSignal() { CloseHandle(event); }
    void signal() { if (!SetEvent(event)) std::abort(); }
    void wait() { if (WaitForSingleObject(event,15000) != WAIT_OBJECT_0) std::abort(); }
};
bool lifetimeRegression() {
    jvmtiEnv key{};
    Observer observer;
    publish(&key,observer);
    TestSignal entered, release, closing, dispatched, enterLate;
    std::atomic<unsigned> order{0};
    unsigned callbackOrder = 0, retirementOrder = 0;
    std::thread callback([&] {
        Admission admission(&key);
        entered.signal();
        release.wait();
        admission.observer->barrier = 17;
        callbackOrder = ++order;
    });
    entered.wait();
    std::thread late([&] {
        dispatched.signal();
        enterLate.wait();
        // No JVMTI functions exist on this key; a late environment call fails.
        loaded(&key,nullptr,0,nullptr,0,nullptr,nullptr);
        generated(&key,"nmethod_entry_barrier",reinterpret_cast<void*>(29),0);
    });
    dispatched.wait();
    std::thread closer([&] {
        closing.signal();
        retire(&key);
        retirementOrder = ++order;
    });
    closing.wait();
    release.signal();
    callback.join();
    closer.join();
    enterLate.signal();
    late.join();
    return callbackOrder == 1 && retirementOrder == 2 && observer.barrier == 17;
}
}

extern "C" __declspec(dllexport) jstring JNICALL
Java_CompiledHandlerSnapshotSmoke_snapshot(JNIEnv* env, jclass fixture, jobject workload, jboolean witness,jboolean implicit) {
    Observation observation;
    observation.ownerEnv = env;
    auto& observer = observation.observer;
    auto& ti = observation.environment;
    JavaVM* vm;
    auto fail = [&](const char* message) -> jstring {
        observation.close();
        env->ThrowNew(env->FindClass("java/lang/AssertionError"), message);
        return nullptr;
    };
    if (implicit) {
        observer.retainedFixture = static_cast<jclass>(env->NewGlobalRef(fixture));
        if (!observer.retainedFixture) return nullptr;
        constexpr const char* names[]{"faulting","implicitCarrier","implicitCaller","implicitRoot"};
        for (auto name : names) {
            auto id = env->GetStaticMethodID(fixture,name,std::strcmp(name,"faulting") == 0
                ? "(LCompiledHandlerSnapshotSmoke$Box;)I" : "(LCompiledHandlerSnapshotSmoke$Box;)V");
            if (env->ExceptionCheck()) return nullptr;
            auto method = MethodAccess::resolve(env,fixture,id);
            if (!method) return fail("Cannot cache implicit VM method identity before callbacks");
            observer.implicitMethods.emplace(id,method);
        }
    }
    if (!lifetimeRegression()) return fail("Snapshot callback admission did not drain before retirement");
    if (env->GetJavaVM(&vm) != JNI_OK || vm->GetEnv(reinterpret_cast<void**>(&ti), JVMTI_VERSION_1_2) != JNI_OK)
        return fail("Cannot create independent snapshot observer");
    publish(ti,observer);
    jvmtiCapabilities capabilities{};
    capabilities.can_generate_compiled_method_load_events = 1;
    if (ti->AddCapabilities(&capabilities) != JVMTI_ERROR_NONE)
        return fail("Cannot configure snapshot observer");
    jvmtiEventCallbacks callbacks{};
    callbacks.CompiledMethodLoad = loaded;
    callbacks.DynamicCodeGenerated = generated;
    if (ti->SetEventCallbacks(&callbacks, sizeof(callbacks)) != JVMTI_ERROR_NONE
            || ti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_DYNAMIC_CODE_GENERATED, nullptr) != JVMTI_ERROR_NONE
            || ti->GenerateEvents(JVMTI_EVENT_DYNAMIC_CODE_GENERATED) != JVMTI_ERROR_NONE
            || ti->SetEventNotificationMode(JVMTI_DISABLE, JVMTI_EVENT_DYNAMIC_CODE_GENERATED, nullptr) != JVMTI_ERROR_NONE
            || ti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_COMPILED_METHOD_LOAD, nullptr) != JVMTI_ERROR_NONE)
        return fail("Cannot enable compiled snapshot observer");
    if (workload) {
        auto type = env->GetObjectClass(workload);
        auto run = env->GetMethodID(type, "run", "()V");
        env->CallVoidMethod(workload, run);
        env->DeleteLocalRef(type);
        if (env->ExceptionCheck()) return nullptr;
    } else if (ti->GenerateEvents(JVMTI_EVENT_COMPILED_METHOD_LOAD) != JVMTI_ERROR_NONE) {
        return fail("Cannot visit compiled snapshot fixtures");
    }
    std::string witnessReport, witnessError;
    if (witness) {
        {
            std::lock_guard lock(callbackMutex);
            observer.witnessBegin = observer.methods.size();
        }
        // One current-state baseline after warmup; this call completes its
        // callbacks but does not freeze code or drain unrelated live events.
        if (ti->GenerateEvents(JVMTI_EVENT_COMPILED_METHOD_LOAD) != JVMTI_ERROR_NONE)
            return fail("Cannot refresh post-warmup checkpoint certificates");
        HandlerCheckpoint::Input input;
        {
            std::lock_guard lock(callbackMutex);
            input = {&observer,checkpointSnapshot,observer.barrier,observer.stub,observer.stubSize,coldSnapshot,implicit != JNI_FALSE};
        }
        auto success = HandlerCheckpoint::run(env,ti,fixture,input,witnessReport,witnessError);
        if (env->ExceptionCheck()) return nullptr;
        if (!success) return fail(witnessError.c_str());
    }
    if (ti->SetEventNotificationMode(JVMTI_DISABLE, JVMTI_EVENT_COMPILED_METHOD_LOAD, nullptr) != JVMTI_ERROR_NONE)
        return fail("Cannot disable compiled snapshot observer");
    observation.close();
    if (observer.error) return fail(observer.error);
    std::string report = "OBSERVER_LIFETIME_OK admittedDrained=1 lateIgnored=1\n" + witnessReport;
    for (const auto& method : observer.methods) {
        report += "SNAPSHOT_RUNTIME method=" + method.name + " error=" + (method.error.empty() ? "none" : method.error)
            + " code=" + std::to_string(method.snapshot.code().size())
            + " edges=" + std::to_string(method.snapshot.edges().size()) + " level=" + std::to_string(method.level)
            + " faults=" + std::to_string(method.snapshot.faults().size())
            + " conventional=" + (method.conventionalFrame ? "1" : "0") + "\n";
        if (method.error.empty() && (method.snapshot.code().empty() || !method.snapshot.address()))
            return fail("Successful snapshot lost its owned code after callback");
        if (method.error.empty() && (!method.snapshot.faults().empty() || !method.snapshot.edges().empty())) {
            const auto& snapshot = method.snapshot;
            char field[128];
            std::snprintf(field, sizeof(field), " address=%llx barrier=%llx entry=%zu allocation=%u bytes=",
                static_cast<unsigned long long>(snapshot.address()), static_cast<unsigned long long>(observer.barrier),
                snapshot.entry(), snapshot.allocation());
            report += snapshot.faults().empty() ? "HANDLER_CODE method=" : "FAULT_CODE method=";
            report += method.name + " level=" + std::to_string(method.level)
                + " conventional=" + (method.conventionalFrame ? "1" : "0");
            report += field;
            constexpr char hex[] = "0123456789abcdef";
            for (auto byte : snapshot.code()) { report += hex[byte >> 4]; report += hex[byte & 15]; }
            report += " faults=";
            if (snapshot.faults().empty()) report += "-";
            for (const auto& edge : snapshot.faults())
                report += std::to_string(edge.source) + ":" + std::to_string(edge.target) + ",";
            report += " handlers=";
            if (snapshot.edges().empty()) report += "-";
            for (const auto& edge : snapshot.edges())
                report += std::to_string(edge.source) + ":" + std::to_string(edge.target) + ":" + (edge.callReturn ? "1," : "0,");
            report += '\n';
        }
        if (method.error.empty() && (method.name == "scalar" || method.name == "unprovenFmaTarget") && method.level == 4) {
            const auto& snapshot = method.snapshot;
            if (!snapshot.edges().empty()) return fail("Scalar fixture has unexpected exceptional edges");
            char field[128];
            std::snprintf(field, sizeof(field), " address=%llx barrier=%llx entry=%zu allocation=%u bytes=",
                static_cast<unsigned long long>(snapshot.address()), static_cast<unsigned long long>(observer.barrier),
                snapshot.entry(), snapshot.allocation());
            report += method.name == "scalar" ? "SCALAR_CODE" : "UNSUPPORTED_CODE";
            report += field;
            constexpr char hex[] = "0123456789abcdef";
            for (auto byte : snapshot.code()) { report += hex[byte >> 4]; report += hex[byte & 15]; }
            report += '\n';
        }
    }
    return env->NewStringUTF(report.c_str());
}
