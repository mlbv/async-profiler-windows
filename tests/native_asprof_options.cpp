/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
// Checks that asprof.exe builds the agent commands of upstream src/main/main.cpp, without attaching.
#include "asprof.h"
#include <cstdio>
#include <cstdlib>
#include <shellapi.h>

using namespace Asprof;

namespace {
int checks;

const JvmLookup lookup{[]() -> DWORD { fail("unexpected jps lookup"); }, [](const std::string&) -> DWORD { fail("unexpected name lookup"); }};

template<class T> void expect(const T& actual, const T& expected, const std::string& context) {
    if (!(actual == expected)) {
        std::fprintf(stderr, "%s: unexpected value\n", context.c_str());
        std::exit(1);
    }
    ++checks;
}
void expect(const std::string& actual, const char* expected, const std::string& context) {
    if (actual != expected) {
        std::fprintf(stderr, "%s: expected <%s> but was <%s>\n", context.c_str(), expected, actual.c_str());
        std::exit(1);
    }
    ++checks;
}

std::string joined(const std::vector<std::string>& args) {
    std::string result;
    for (const auto& arg : args) result += (result.empty() ? "" : " ") + arg;
    return result;
}

Options parse(std::vector<std::string> args) { return Options::parse(args, lookup); }

// Asserts output + format + params, the order in which asprof appends them after file=.
Options agent(const char* expected, std::vector<std::string> args) {
    auto o = parse(args);
    expect(o.output + o.format + o.params, expected, joined(args));
    return o;
}

void failure(const char* message, std::vector<std::string> args) {
    try {
        (void)parse(args);
    } catch (const Failure& e) {
        expect(e.message, message, joined(args));
        expect(e.code, 1, "exit code of " + joined(args));
        return;
    }
    std::fprintf(stderr, "Accepted %s\n", joined(args).c_str());
    std::exit(1);
}

void options() {
    agent(",event=cpu,interval=1ms", {"start", "-e", "cpu", "-i", "1ms", "1234"});
    agent(",event=wall,interval=5ms", {"--event", "wall", "--interval", "5ms", "1234"});
    agent(",event=cpu/event=0xc0:umask=0/", {"-e", "cpu/event=0xc0,umask=0/", "1234"});
    agent(",event=rC0", {"-e", "rC0", "1234"});
    agent(",event=trace:{01234567-89ab-cdef-0123-456789abcdef}/7/2", {"-e", "trace:{01234567-89ab-cdef-0123-456789abcdef}/7/2", "1"});
    agent(",jstackdepth=64/12,threads", {"-j", "64/12", "-t", "1"});
    agent(",jstackdepth=8,threads", {"--jstackdepth", "8", "--threads", "1"});
    agent(",simple,norm,sig,ann,lib,dot", {"-s", "-n", "-g", "-a", "-l", "--dot", "1"});
    agent(",simple,norm,sig,ann,lib", {"--simple", "--norm", "--sig", "--ann", "--lib", "1"});
    agent(",include=App.*,exclude=*Idle*,include=*Worker*", {"-I", "App.*", "--exclude", "*Idle*", "--include", "*Worker*", "1"});
    agent(",loglevel=debug,loglevel=none", {"-L", "debug", "--log", "none", "1"});
    agent(",features=stats+vtable+comptask", {"-F", "stats,vtable,comptask", "1"});
    agent(",features=mixed", {"--features", "mixed", "1"});
    agent(",ithread=worker-*,ithread=main,xthread=worker-idle",
          {"--ithread", "worker-*", "--ithread", "main", "--xthread", "worker-idle", "1"});
    agent(",ratelimit=cpu:100;alloc:20;wall:0", {"--ratelimit", "cpu:100,alloc:20,wall:0", "1"});
    agent(",ratelimit=lock:10;trace:5,ratelimit=span:3", {"--ratelimit", "lock:10;trace:5", "--ratelimit", "span:3", "1"});
    agent(",title=a&amp;b&lt;c&gt;d&#44;e", {"--title", "a&b<c>d,e", "1"});
    agent(",width=1200,height=16,minwidth=0.5", {"--width", "1200", "--height", "16", "--minwidth", "0.5", "1"});
    agent(",reverse,inverted,samples,total", {"--reverse", "--inverted", "--samples", "--total", "1"});
    for (std::string name : {"alloc", "nativemem", "nativelock", "lock", "wall", "trace", "chunksize", "chunktime", "cstack", "signal",
                             "clock", "begin", "end", "target-cpu", "proc", "memlimit", "ithread", "xthread"}) {
        agent(("," + name + "=v").c_str(), {"--" + name, "v", "1"});
    }
    for (std::string name : {"all", "live", "nobatch", "nofree", "nostop", "record-cpu", "sched", "tlab", "ttsp"}) {
        agent(("," + name).c_str(), {"--" + name, "1"});
    }
    agent(",alluser", {"--all-user", "1"});
    agent("jfr,jfrsync=profile", {"--jfrsync", "profile", "1"});
    agent("jfr,jfropts=mem", {"--jfropts", "mem", "1"});
    agent("traces=200,flat=200,simple", {"-o", "traces=200,flat=200", "-s", "1"});
    agent(",event=module.dll!Function", {"--probe", "module.dll!Function", "1"});
    agent(",event=cpu,event=wall", {"-e", "cpu", "-e", "wall", "1"});
    agent(",include=\xe5\x90\x8c\xe6\xad\xa5", {"-I", "\xe5\x90\x8c\xe6\xad\xa5", "1"});
}

void actions() {
    expect(parse({"1234"}).action, "collect", "default action");
    for (std::string action : {"start", "resume", "stop", "dump", "status", "metrics", "list", "collect"}) {
        auto o = parse({action, "1234"});
        expect(o.action, action.c_str(), action);
        expect(o.pid, DWORD(1234), action + " pid");
        expect(o.jattach, false, action + " is a profiler action");
    }
    // asprof switches collect to start, and only collect.
    expect(parse({"--timeout", "5", "1234"}).action, "start", "timeout");
    expect(parse({"1234", "--loop", "1m"}).action, "start", "loop");
    expect(parse({"resume", "--loop", "1m", "1234"}).action, "resume", "loop resume");
    expect(parse({"--timeout", "5", "stop", "1234"}).action, "stop", "later action");
    expect(parse({"launch", "--timeout", "5", "--", "-version"}).action, "launch", "launch timeout");
    expect(parse({"-d", "30", "1234"}).duration, 30, "duration");
    expect(parse({"1234"}).duration, 60, "default duration");
    expect(parse({"-d", "1.5", "1"}).duration, 1, "atoi duration");
    expect(parse({"-d", "5s", "1"}).duration, 5, "atoi suffix");
    expect(parse({"-d", "x", "1"}).duration, 0, "atoi text");
    expect(parse({"-d", "-3", "1"}).duration, -3, "atoi sign");
    expect(parse({"-d", "99999999999", "1"}).duration, 0x7fffffff, "saturated duration");
    expect(parse({"-d", "-99999999999", "1"}).duration, int(0x80000000), "saturated negative duration");
    expect(*parse({"-f", "out.html", "1"}).file, std::string("out.html"), "file");
    expect(parse({"1"}).file.has_value(), false, "temporary file");
    expect(*parse({"--libpath", "C:/a,b/asyncProfiler.dll", "1"}).libpath, std::string("C:/a,b/asyncProfiler.dll"), "libpath");
}

void jattach() {
    for (std::string action : {"load", "jcmd", "threaddump", "dumpheap", "inspectheap"}) {
        auto o = parse({action, "1234", "-h", "--version", "x,y"});
        expect(o.jattach, true, action);
        expect(o.pid, DWORD(1234), action + " pid");
        // Parsing ends at the PID; the rest belongs to the jattach command.
        expect(o.arguments, std::vector<std::string>{"-h", "--version", "x,y"}, action + " arguments");
        expect(o.help || o.version, false, action + " passes -h/-v");
    }
    expect(parse({"jcmd", "-L", "info", "1234", "VM.flags", "-all"}).arguments, std::vector<std::string>{"VM.flags", "-all"}, "jcmd");
}

void pids() {
    expect(parse({"123abc"}).pid, DWORD(123), "atoi pid");
    expect(parse({"4294967295"}).pid, DWORD(4294967295u), "largest pid");
    failure("Process 4294967296 not found", {"4294967296"});
    failure("Process 99999999999999999999 not found", {"0099999999999999999999"});
    failure("Unrecognized option: 456", {"123", "456"});
    expect(parse({"0", "7"}).pid, DWORD(7), "zero is not a pid");
    expect(parse({"start"}).pid, DWORD(0), "missing pid");
    failure("Unrecognized option: Name", {"Name", "1"});
    failure("Unrecognized option: -1", {"-1"});
    failure("unexpected jps lookup", {"jps"});
    failure("unexpected name lookup", {"MyApp"});
}

void errors() {
    failure("Unrecognized option: --bogus", {"--bogus", "1"});
    failure("Unrecognized option: --option", {"--option", "x", "1"});
    failure("Unrecognized option: --file", {"--file", "x", "1"});
    failure("Unrecognized option: --filter", {"--filter", "120-127", "1"});
    failure("Unrecognized option: --server", {"--server", "127.0.0.1:8000", "1"});
    for (std::string option : {"--ithread", "--xthread", "--ratelimit"}) {
        failure("Missing required parameter", {"1", option});
    }
    failure("Option values cannot contain commas: worker,stop", {"--ithread", "worker,stop", "1"});
    failure("Option values cannot contain control characters", {"--ratelimit", "cpu:1\n", "1"});
    failure("Unrecognized option: record", {"record", "1"});
    failure("Unrecognized option: --", {"start", "--", "1"});
    failure("Missing required parameter", {"-f"});
    failure("Missing required parameter", {"1", "-e"});
    failure("Option values cannot contain commas: a,b.jfr", {"-f", "a,b.jfr", "1"});
    failure("Option values cannot contain commas: read,alloc=1", {"-e", "read,alloc=1", "1"});
    failure("Option values cannot contain commas: App,start", {"-I", "App,start", "1"});
    failure("Option values cannot contain commas: 2,start", {"--timeout", "2,start", "1"});
    failure("Option values cannot contain control characters", {"-f", "a\nb", "1"});
    failure("Option values cannot contain control characters", {"-o", std::string("flat\0", 5), "1"});
    failure("Option values cannot contain control characters", {"--title", "a\tb", "1"});
    failure("Unrecognized option: -x", {"-x", "-h"});
}

void immediate() {
    expect(parse({"-h", "--bogus"}).help, true, "-h");
    expect(parse({"1", "--help"}).help, true, "--help");
    expect(parse({"-v", "--bogus"}).version, true, "-v");
    expect(parse({"--version"}).version, true, "--version");
}

void windows() {
    for (std::string action : {"ps", "inspect"}) expect(parse({action}).action, action.c_str(), action);
    auto launch = parse({"launch", "-e", "wall", "-f", "out.jfr", "--java", "C:/jdk/bin/java.exe", "--", "-cp", "app.jar", "Main", "-f"});
    expect(launch.action, "launch", "launch");
    expect(*launch.java, std::string("C:/jdk/bin/java.exe"), "launch java");
    expect(launch.arguments, std::vector<std::string>{"-cp", "app.jar", "Main", "-f"}, "launch arguments");
    expect(launch.params, ",event=wall", "launch options");
    auto program = parse({"launch", "--", "app.exe", "--", "x"});
    expect(program.arguments, std::vector<std::string>{"app.exe", "--", "x"}, "native launch arguments");
    auto transfer = parse({"start", "--fdtransfer", "1"});
    const std::string prefix = "\\\\.\\pipe\\async-profiler-asprof-";
    expect(transfer.fdtransfer->compare(0, prefix.size(), prefix), 0, *transfer.fdtransfer);
    expect(transfer.params, (",fdtransfer=" + *transfer.fdtransfer).c_str(), "fdtransfer parameter");
}

void outputs() {
    expect(jfrOutput(parse({"1"}), "out.jfr"), true, "jfr extension");
    expect(jfrOutput(parse({"1"}), "out.JFR"), false, "case-sensitive extension");
    expect(jfrOutput(parse({"1"}), "C:/dir.jfr/out"), false, "directory extension");
    expect(jfrOutput(parse({"1"}), "out.html"), false, "html extension");
    expect(jfrOutput(parse({"-o", "jfr", "1"}), "out.html"), true, "explicit jfr");
    expect(jfrOutput(parse({"--jfrsync", "profile", "1"}), "out"), true, "jfrsync");
    expect(jfrOutput(parse({"-o", "collapsed", "1"}), "out.jfr"), false, "explicit collapsed");
    expect(jfrOutput(parse({"--jfropts", "mem", "-o", "flat", "1"}), "out"), true, "params follow -o");
    expect(jfrOutput(parse({"-o", "jfr,flat=10", "1"}), "out"), false, "last selector");
    for (const std::string url : {"http://localhost:4318/v1/profiles", "https://example.test/a%20b.jfr"}) {
        expect(isUrl(url), true, url);
        expect(*parse({"-f", url, "1"}).file, url, "URL passthrough");
        expect(jfrOutput(parse({"1"}), url), false, "URL defaults to OTLP");
        expect(jfrOutput(parse({"-o", "jfr", "1"}), url), true, "explicit output overrides URL");
    }
    for (const std::string file : {"out.jfr", "C:/http/profile.jfr", "HTTP://example.test/out.jfr", "ftp://host/out.jfr"}) {
        expect(isUrl(file), false, file);
    }
}

void jpsNames() {
    expect(Jvms::jpsName("com.example.Main arg"), "Main", "main class");
    expect(Jvms::jpsName("Main"), "Main", "default package");
    expect(Jvms::jpsName("C:\\apps\\server.jar --port 1"), "server.jar", "jar");
    expect(Jvms::jpsName("lib.my.jar"), "lib.my.jar", "dotted jar");
    expect(Jvms::jpsName("jdk.compiler/com.sun.tools.javac.Main x"), "Main", "module");
    expect(Jvms::jpsName(""), "", "unavailable");
}

void quoting() {
    expect(commandLine({L"a", L"b c", L"", L"q\"x", L"tr\\", L"x\\\"y", L"\\\\server\\share\\"}),
          std::wstring(L"a \"b c\" \"\" \"q\\\"x\" tr\\ \"x\\\\\\\"y\" \\\\server\\share\\"), "quoting");
    int count = 0;
    auto line = commandLine({L"p", L"two  spaces\\\"end", L"\t", L"\u00fc\U0001F642"});
    auto parsed = CommandLineToArgvW(line.c_str(), &count);
    expect(count, 4, "argument count");
    expect(std::wstring(parsed[1]), std::wstring(L"two  spaces\\\"end"), "round trip");
    expect(std::wstring(parsed[2]), std::wstring(L"\t"), "tab round trip");
    expect(std::wstring(parsed[3]), std::wstring(L"\u00fc\U0001F642"), "unicode round trip");
    LocalFree(parsed);
}
}

int main() {
    options();
    actions();
    jattach();
    pids();
    errors();
    immediate();
    windows();
    outputs();
    jpsNames();
    quoting();
    std::printf("ASPROF_OPTIONS_OK checks=%d\n", checks);
}
