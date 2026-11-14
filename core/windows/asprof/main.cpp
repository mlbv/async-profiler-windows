/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Derived from upstream src/main/main.cpp; modified for Windows x86-64.
 */
#include "asprof.h"
#include <algorithm>
#include <chrono>

namespace Asprof {
namespace {
const char USAGE[] =
    "Usage: asprof [action] [options] <pid>\n"
    "Actions:\n"
    "  start               start profiling and return immediately\n"
    "  resume              resume profiling without resetting collected data\n"
    "  stop                stop profiling\n"
    "  dump                dump collected data without stopping profiling session\n"
    "  status              print profiling status\n"
    "  metrics             print profiler metrics in Prometheus format\n"
    "  list                list profiling events supported by the target JVM\n"
    "  load                load agent library (jattach action)\n"
    "  jcmd                run JVM diagnostic command (jattach action)\n"
    "  collect             collect profile for the specified period of time\n"
    "                      and then stop (default action)\n"
    "Windows actions without <pid>:\n"
    "  launch              start a program with the profiler: launch [options] -- <java arguments>\n"
    "                      or launch [options] -- <program.exe> [arguments]\n"
    "  ps                  list attachable JVMs\n"
    "  inspect             print profiler DLL exports, imports, architecture, version and SHA-256 as JSON\n"
    "Options:\n"
    "  -e event            profiling event: cpu|alloc|nativemem|lock|cache-misses etc.\n"
    "  -d duration         run profiling for <duration> seconds\n"
    "  -f filename         file name or http(s) URL to submit profiles to\n"
    "  -i interval         sampling interval in nanoseconds\n"
    "  -j jstackdepth      maximum Java stack depth\n"
    "  -t, --threads       profile different threads separately\n"
    "  -s, --simple        simple class names instead of FQN\n"
    "  -n, --norm          normalize names of hidden classes / lambdas\n"
    "  -g, --sig           print method signatures\n"
    "  -a, --ann           annotate Java methods\n"
    "  -l, --lib           prepend library names\n"
    "  --dot               dotted class names\n"
    "  -o fmt              output format: flat|traces|collapsed|flamegraph|tree|jfr|otlp\n"
    "  -I include          output only stack traces containing the specified pattern\n"
    "  -X exclude          exclude stack traces with the specified pattern\n"
    "  -L level            log level: debug|info|warn|error|none\n"
    "  -F features         advanced stack trace features: mixed, vtable, comptask, pcaddr\n"
    "  -v, --version       display version string\n"
    "\n"
    "  --title string      FlameGraph title\n"
    "  --minwidth pct      skip frames smaller than pct%\n"
    "  --reverse           generate stack-reversed FlameGraph / Call tree (defaults to icicle graph)\n"
    "  --inverted          toggles the layout for reversed stacktraces from icicle to flamegraph\n"
    "                      and for default stacktraces from flamegraph to icicle\n"
    "\n"
    "  --loop time         run profiler in a loop\n"
    "  --alloc bytes       allocation profiling interval in bytes\n"
    "  --tlab              use TLAB events for allocation profiling\n"
    "  --live              build allocation profile from live objects only\n"
    "  --nativemem bytes   native allocation profiling interval in bytes\n"
    "  --nofree            do not collect free calls in native allocation profiling\n"
    "  --trace method      Method to be instrumented with optional latency threshold\n"
    "  --lock time         lock profiling threshold in nanoseconds\n"
    "  --nativelock time   critical section/SRW lock profiling threshold in nanoseconds\n"
    "  --wall interval     wall clock profiling interval\n"
    "  --nobatch           legacy wall clock sampling without batch events\n"
    "  --ithread pattern   profile only threads matching the name pattern\n"
    "  --xthread pattern   skip threads matching the name pattern\n"
    "  --proc interval     process sampling interval (default: 30s)\n"
    "  --all               shorthand for enabling cpu, wall, alloc, live,\n"
    "                      nativemem and lock profiling simultaneously\n"
    "  --total             accumulate the total value (time, bytes, etc.)\n"
    "  --all-user          only include user-mode events\n"
    "  --sched             group threads by scheduling policy\n"
    "  --cstack mode       how to traverse C stack: fp|dwarf|vm|no\n"
    "  --signal num        use alternative callback ID for cpu or wall clock profiling\n"
    "  --clock source      clock source for JFR timestamps: tsc|monotonic\n"
    "  --begin function    begin profiling when function is executed\n"
    "  --end function      end profiling when function is executed\n"
    "  --ttsp              only time-to-safepoint profiling\n"
    "  --nostop            do not stop profiling outside --begin/--end window\n"
    "  --memlimit bytes    limit size of the stack trace storage\n"
    "  --ratelimit limits  limit the number of JFR events emitted per second\n"
    "  --jfropts opts      JFR recording options: mem\n"
    "  --jfrsync config    synchronize profiler with JFR recording\n"
    "  --libpath path      full path to asyncProfiler.dll\n"
    "  --fdtransfer        run asprof-helper.exe as the ETW broker for\n"
    "                      the non-elevated target (requires an elevated asprof)\n"
    "  --target-cpu cpu    sample threads on a specific CPU (ETW events only, default: -1)\n"
    "  --probe target      native entry probe: symbol or module.dll!symbol\n"
    "  --java path         java.exe for a JVM launch (default: JAVA_HOME, then PATH)\n"
    "\n"
    "<pid> is a numeric process ID of the target JVM\n"
    "      or 'jps' keyword to find running JVM automatically\n"
    "      or the application name as it would appear in the jps tool\n"
    "\n"
    "Example: asprof -d 30 -f profile.html 3456\n"
    "         asprof start -i 1ms jps\n"
    "         asprof stop -o flat jps\n"
    "         asprof -d 5 -e alloc MyAppName\n"
    "         asprof --all -f profile.jfr MyAppName\n";

HANDLE interruptEvent;

BOOL WINAPI interrupted(DWORD) {
    SetEvent(interruptEvent);
    return TRUE;
}

// Prints and removes a file written by the agent, as upstream's print_file does.
void print(const std::wstring& path, void (*destination)(std::string_view)) {
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
    if (!file) return;
    char buffer[65536];
    DWORD read = 0;
    while (ReadFile(file.value, buffer, sizeof(buffer), &read, nullptr) && read) destination(std::string_view(buffer, read));
    file = Handle();
    // Upstream ignores unlink failures; a temporary recording can remain open in the target.
    DeleteFileW(path.c_str());
}

std::wstring temporaryFile(const wchar_t* prefix) {
    WCHAR path[MAX_PATH];
    if (!GetTempFileNameW(temporaryDirectory().c_str(), prefix, 0, path)) fail("Cannot create a temporary file: " + windowsError(GetLastError()));
    return path;
}

// Loads the profiler with one command per attach, as jattach's load action does.
class Profiler {
public:
    Profiler(DWORD pid, const Library& library, std::wstring log) : _jvm(pid), _library(library), log(std::move(log)) {}
    const std::wstring log;
    HANDLE process() const { return _jvm.process(); }

    // Returns the Agent_OnAttach result, or -1 after reporting a load failure.
    int load(const std::string& options) {
        // Retain a successful load before a command that can fail, since the JVM may unload a
        // first agent load that returns an error.
        auto response = temporaryFile(L"api");
        int status;
        try {
            status = loadNative("version,file=" + Options::value(utf8(response)));
        } catch (...) {
            DeleteFileW(response.c_str());
            throw;
        }
        WIN32_FILE_ATTRIBUTE_DATA attributes;
        bool confirmed = GetFileAttributesExW(response.c_str(), GetFileExInfoStandard, &attributes)
                && (attributes.nFileSizeLow || attributes.nFileSizeHigh);
        DeleteFileW(response.c_str());
        if (status != 0) return status;
        if (!confirmed) fail("Native profiler did not confirm initialization");
        return loadNative(options);
    }

private:
    Attach _jvm;
    const Library& _library;

    int loadNative(const std::string& options) {
        auto dll = utf8(_library.dll);
        auto reply = _jvm.execute("load", {ansi(dll), "true", options + ",log=" + Options::value(utf8(log))});
        std::string message;
        auto result = loadResult(reply, message);
        if (result == -1) writeErr(message.empty() ? "Target JVM failed to load " + dll + "\n" : message);
        return result;
    }
};

// Runs one agent command, mirroring upstream's run_jattach: the agent log goes to stderr.
void run(Profiler& target, const std::string& command) {
    int status;
    try {
        status = target.load(command);
    } catch (...) {
        print(target.log, writeErr);
        throw;
    }
    print(target.log, writeErr);
    if (status != 0) fail("", status & 0xff);
}

// Waits at least -d seconds, as upstream; Ctrl+C ends the wait early. Returns false if the target exited.
bool collect(const Options& o, HANDLE process) {
    using std::chrono::steady_clock;
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    interruptEvent = event.value;
    SetConsoleCtrlHandler(interrupted, TRUE);
    auto deadline = steady_clock::now() + std::chrono::seconds(o.duration);
    bool alive = true, stopped = false;
    for (steady_clock::duration remaining; alive && !stopped && (remaining = deadline - steady_clock::now()) > steady_clock::duration::zero();) {
        HANDLE handles[] = {process, event.value};
        auto milliseconds = std::chrono::ceil<std::chrono::milliseconds>(remaining).count();
        auto result = WaitForMultipleObjects(2, handles, FALSE, static_cast<DWORD>(std::min<long long>(milliseconds, 0x7fffffff)));
        alive = result != WAIT_OBJECT_0;
        stopped = result == WAIT_OBJECT_0 + 1;
    }
    // Upstream restores the default Ctrl+C action before the final stop.
    SetConsoleCtrlHandler(interrupted, FALSE);
    if (alive) writeErr(stopped ? "Interrupted\n" : "Done\n");
    return alive;
}

// JFR dump/stop output is written to a temporary file and atomically replaces the destination.
void snapshot(const Options& o, Profiler& target, const std::string& file) {
    std::wstring destination;
    if (file.find('%') != std::string::npos) {
        OutputFiles outputs;
        run(target, "resolve,file=" + file + outputs.options());
        destination = outputs.single();
    } else {
        auto path = wide(file);
        for (auto& c : path) if (c == L'/') c = L'\\';
        destination = absolutePath(path);
    }
    createParents(destination);
    // The agent creates this name exclusively; its .jfr extension keeps JFR output selected.
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    auto snapshot = destination.substr(0, destination.find_last_of(L'\\') + 1) + L"asprof-snapshot-"
            + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(counter.QuadPart) + L".jfr";
    try {
        run(target, o.action + ",file=" + Options::value(utf8(snapshot)) + "," + o.output + o.format + o.params);
        validateJfr(snapshot);
        if (!MoveFileExW(snapshot.c_str(), destination.c_str(), MOVEFILE_REPLACE_EXISTING)) {
            fail("Cannot replace " + utf8(destination) + ": " + windowsError(GetLastError()));
        }
    } catch (...) {
        DeleteFileW(snapshot.c_str());
        throw;
    }
}

void profile(const Options& o, const Library& library) {
    auto self = std::to_wstring(GetCurrentProcessId()), pid = std::to_wstring(o.pid);
    auto temporary = temporaryDirectory();
    bool useTmpFile = !o.file;
    auto file = useTmpFile ? Options::value(utf8(temporary + L"asprof." + self + L"." + pid)) : *o.file;
    // The agent closes a log named asprof-log.* after every command.
    Profiler target(o.pid, library, temporary + L"asprof-log." + self + L"." + pid);
    bool url = isUrl(file);
    auto location = ",file=" + file + (useTmpFile || url ? "" : OutputFiles::base()) + "," + o.output + o.format;
    if (o.action == "collect") {
        if (o.fdtransfer) startBroker(o.pid, *o.fdtransfer, library);
        run(target, "start,quiet" + location + o.params);
        writeErr("Profiling for " + std::to_string(o.duration) + " seconds\n");
        if (collect(o, target.process())) {
            // A JFR recording is finalized in its own file; a stop file would request a copy.
            run(target, !url && jfrOutput(o, file) ? "stop,jfr" + o.format : "stop" + location);
        } else {
            writeErr("Process exited\n");
        }
    } else if (o.action == "start" || o.action == "resume") {
        if (o.fdtransfer) startBroker(o.pid, *o.fdtransfer, library);
        run(target, o.action + location + o.params);
    } else if ((o.action == "stop" || o.action == "dump") && !url && jfrOutput(o, file)) {
        snapshot(o, target, file);
    } else {
        run(target, o.action + location + o.params);
    }
    if (useTmpFile) print(wide(file), writeOut);
}

std::wstring javaExecutable(const Options& o) {
    if (o.java) return wide(*o.java);
    WCHAR home[32768];
    auto length = GetEnvironmentVariableW(L"JAVA_HOME", home, 32768);
    if (length && length < 32768) return std::wstring(home, length) + L"\\bin\\java.exe";
    WCHAR path[32768];
    if (!SearchPathW(nullptr, L"java.exe", nullptr, 32768, path, nullptr)) fail("Cannot find java.exe: set JAVA_HOME, add java.exe to PATH or pass --java");
    return path;
}

// A first argument ending in .exe names a native program, which asprof-helper.exe starts with the
// profiler preloaded and the start command in ASPROF_COMMAND; otherwise the arguments start a JVM
// that loads the profiler with -agentpath.
int launch(const Options& o, const Library& library) {
    if (o.arguments.empty()) fail("Usage: asprof launch [options] -- <java arguments> | <program.exe> [arguments]");
    if (o.fdtransfer) fail("--fdtransfer is not supported by launch");
    if (o.durationGiven && o.timeout) fail("Use either -d or --timeout with launch");
    const auto& program = o.arguments.front();
    bool nativeProgram = program.size() >= 4 && _stricmp(program.c_str() + program.size() - 4, ".exe") == 0;
    if (nativeProgram && o.java) fail("--java applies only to JVM launches");
    bool useTmpFile = !o.file;
    auto file = useTmpFile ? utf8(temporaryDirectory()) + "asprof." + std::to_string(GetCurrentProcessId()) + ".launch" : *o.file;
    bool url = isUrl(file);
    OutputFiles outputs;
    auto options = "start,file=" + Options::value(file) + outputs.options(!url) + "," + o.output + o.format + o.params
            + (o.durationGiven ? ",timeout=" + std::to_string(o.duration) : "");
    std::vector<std::wstring> command;
    if (nativeProgram) {
        command = {library.helper(), L"--preload", library.dll, L"--"};
        if (!SetEnvironmentVariableW(L"ASPROF_COMMAND", wide(options).c_str())) fail("Cannot set ASPROF_COMMAND: " + windowsError(GetLastError()));
    } else {
        command = {javaExecutable(o), L"-agentpath:" + library.dll + L"=" + wide(options)};
    }
    for (const auto& argument : o.arguments) command.push_back(wide(argument));
    auto line = commandLine(command);
    STARTUPINFOW startup{sizeof(startup)};
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(command.front().c_str(), line.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &startup, &process)) {
        fail("Cannot start " + utf8(command.front()) + ": " + windowsError(GetLastError()));
    }
    Handle child(process.hProcess), thread(process.hThread);
    // The helper's PID is not the program's; %p in the output name expands to the program's PID.
    if (!nativeProgram) writeErr("Launched PID " + std::to_string(process.dwProcessId) + "\n");
    // Ctrl+C reaches the launched process, which finalizes its profile when it exits.
    SetConsoleCtrlHandler(nullptr, TRUE);
    WaitForSingleObject(child.value, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(child.value, &code);
    // Without output, the process failed before profiling started; it or the helper reported why.
    auto files = outputs.files();
    if (url || (code != 0 && files.empty())) return static_cast<int>(code);
    outputs.verify(jfrOutput(o, file));
    if (useTmpFile) print(wide(file), writeOut);
    return static_cast<int>(code);
}

int execute(const Options& o) {
    if (o.help) {
        writeOut(USAGE);
        return 0;
    }
    if (o.version) {
        writeOut("Async-profiler " PROFILER_VERSION " built on " __DATE__ "\n");
        return 0;
    }
    if (o.java && o.action != "launch") fail("--java is supported only by launch");
    if (o.action == "ps" || o.action == "inspect" || o.action == "launch") {
        if (o.pid != 0) fail(o.action + " does not accept a PID");
        if (o.action == "ps") {
            for (const auto& jvm : Jvms::list()) writeOut(std::to_string(jvm.pid) + "\t" + jvm.command + "\n");
            return 0;
        }
        auto library = Library::resolve(o.libpath);
        if (o.action == "launch") return launch(o, library);
        writeOut(library.inspect());
        return 0;
    }
    if (o.pid == 0) {
        writeOut(USAGE);
        return 1;
    }
    if (o.jattach) return jattach(o.pid, o.action, o.arguments);
    profile(o, Library::resolve(o.libpath));
    return 0;
}
}

// jattach actions: the request goes to HotSpot unchanged, and the reply is mirrored to stdout.
int jattach(DWORD pid, const std::string& action, const std::vector<std::string>& arguments) {
    std::vector<std::string> args;
    for (const auto& argument : arguments) args.push_back(ansi(argument));
    // jattach sends jcmd's command line as one argument and at most three arguments otherwise.
    size_t limit = action == "jcmd" ? 1 : 3;
    if (args.size() > limit) {
        for (size_t i = limit; i < args.size(); ++i) args[limit - 1] += " " + args[i];
        args.resize(limit);
    }
    Attach jvm(pid);
    writeOut("Connected to remote JVM\n");
    auto reply = jvm.execute(action, args);
    writeOut("JVM response code = " + std::to_string(reply.status) + "\n" + reply.body + "\n");
    std::string message;
    auto result = action == "load" ? loadResult(reply, message) : reply.status;
    return result & 0xff;
}
}

int wmain(int argc, wchar_t** argv) {
    using namespace Asprof;
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) args.push_back(utf8(argv[i]));
    int code;
    try {
        code = execute(Options::parse(args, {Jvms::newest, Jvms::named}));
    } catch (const Failure& failure) {
        if (!failure.message.empty()) writeErr(failure.message + "\n");
        code = failure.code;
    }
    return code;
}
