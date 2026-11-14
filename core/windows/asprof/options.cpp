/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "asprof.h"
#include <cstdio>
#include <deque>

namespace Asprof {
namespace {
std::string next(std::deque<std::string>& args) {
    if (args.empty()) fail("Missing required parameter");
    auto value = std::move(args.front());
    args.pop_front();
    return value;
}

const std::string& list(const std::string& value) {
    for (unsigned char c : value) {
        if (c < 32) fail("Option values cannot contain control characters");
    }
    return value;
}

std::string replace(std::string text, std::string_view from, std::string_view to) {
    for (size_t at = 0; (at = text.find(from, at)) != std::string::npos; at += to.size()) text.replace(at, from.size(), to);
    return text;
}

bool digit(char c) { return c >= '0' && c <= '9'; }

// C atoi, saturating instead of undefined overflow.
int atoi(const std::string& text) {
    size_t at = 0;
    while (at < text.size() && (text[at] == ' ' || (text[at] >= '\t' && text[at] <= '\r'))) ++at;
    bool negative = at < text.size() && text[at] == '-';
    if (at < text.size() && (text[at] == '-' || text[at] == '+')) ++at;
    long long value = 0;
    for (; at < text.size() && digit(text[at]); ++at) {
        value = value * 10 + (text[at] - '0');
        if (value > 0x80000000LL) value = 0x80000000LL;
    }
    if (negative) return static_cast<int>(-value);
    return static_cast<int>(value > 0x7fffffffLL ? 0x7fffffffLL : value);
}

DWORD parsePid(const std::string& arg) {
    size_t end = 0;
    while (end < arg.size() && digit(arg[end])) ++end;
    auto digits = arg.substr(0, end);
    size_t first = digits.find_first_not_of('0');
    auto significant = first == std::string::npos ? std::string("0") : digits.substr(first);
    if (significant.size() > 10 || (significant.size() == 10 && significant > "4294967295")) fail("Process " + significant + " not found");
    return static_cast<DWORD>(std::stoull(significant));
}

bool startsWith(const std::string& text, std::string_view prefix) { return text.compare(0, prefix.size(), prefix) == 0; }

bool is(const std::string& arg, std::initializer_list<std::string_view> names) {
    for (auto name : names) if (arg == name) return true;
    return false;
}
}

const std::string& Options::value(const std::string& value) {
    if (value.find(',') != std::string::npos) fail("Option values cannot contain commas: " + value);
    return list(value);
}

std::string brokerPipeName() {
    FILETIME now;
    GetSystemTimePreciseAsFileTime(&now);
    auto micros = ((static_cast<std::uint64_t>(now.dwHighDateTime) << 32) | now.dwLowDateTime) / 10;
    char name[96];
    std::snprintf(name, sizeof(name), "\\\\.\\pipe\\async-profiler-asprof-%lu-%08x", GetCurrentProcessId(), static_cast<unsigned>(micros));
    return name;
}

Options Options::parse(const std::vector<std::string>& argv, const JvmLookup& lookup) {
    Options o;
    std::deque<std::string> args(argv.begin(), argv.end());
    while (!args.empty() && !(o.jattach && o.pid != 0)) {
        auto arg = next(args);
        auto name = arg.size() > 2 ? arg.substr(2) : std::string();
        if (is(arg, {"start", "resume", "stop", "dump", "status", "metrics", "list", "collect"})) {
            o.action = arg;
        } else if (is(arg, {"load", "jcmd", "threaddump", "dumpheap", "inspectheap"})) {
            o.action = arg;
            o.jattach = true;
        } else if (is(arg, {"launch", "ps", "inspect"})) {
            o.action = arg;
        } else if (is(arg, {"-h", "--help"})) {
            o.help = true;
            return o;
        } else if (is(arg, {"-v", "--version"})) {
            o.version = true;
            return o;
        } else if (arg == "-d") {
            o.duration = atoi(next(args));
            o.durationGiven = true;
        } else if (arg == "-f") {
            o.file = value(next(args));
        } else if (arg == "-o") {
            // Several dump options may be combined, e.g. traces=200,flat=200.
            o.output = list(next(args));
        } else if (is(arg, {"-e", "--event"})) {
            auto event = next(args);
            // PMU event, e.g. cpu/umask=0x1,event=0xd3/
            o.params += ",event=" + (event.find(',') != std::string::npos && event.back() == '/' ? replace(list(event), ",", ":") : value(event));
        } else if (is(arg, {"-i", "--interval"})) {
            o.params += ",interval=" + value(next(args));
        } else if (is(arg, {"-j", "--jstackdepth"})) {
            o.params += ",jstackdepth=" + value(next(args));
        } else if (is(arg, {"-t", "--threads"})) {
            o.params += ",threads";
        } else if (is(arg, {"-s", "--simple"})) {
            o.format += ",simple";
        } else if (is(arg, {"-n", "--norm"})) {
            o.format += ",norm";
        } else if (is(arg, {"-g", "--sig"})) {
            o.format += ",sig";
        } else if (is(arg, {"-a", "--ann"})) {
            o.format += ",ann";
        } else if (is(arg, {"-l", "--lib"})) {
            o.format += ",lib";
        } else if (arg == "--dot") {
            // Documented by upstream, although its v4.5 parser omits it.
            o.format += ",dot";
        } else if (is(arg, {"-I", "--include"})) {
            o.format += ",include=" + value(next(args));
        } else if (is(arg, {"-X", "--exclude"})) {
            o.format += ",exclude=" + value(next(args));
        } else if (is(arg, {"-L", "--log"})) {
            o.format += ",loglevel=" + value(next(args));
        } else if (is(arg, {"-F", "--features"})) {
            o.format += ",features=" + replace(list(next(args)), ",", "+");
        } else if (arg == "--title") {
            auto title = replace(list(next(args)), "&", "&amp;");
            o.format += ",title=" + replace(replace(replace(title, "<", "&lt;"), ">", "&gt;"), ",", "&#44;");
        } else if (is(arg, {"--width", "--height", "--minwidth"})) {
            o.format += "," + name + "=" + value(next(args));
        } else if (is(arg, {"--reverse", "--inverted", "--samples", "--total"})) {
            o.format += "," + name;
        } else if (is(arg, {"--alloc", "--nativemem", "--nativelock", "--lock", "--wall", "--trace", "--chunksize", "--chunktime",
                            "--cstack", "--signal", "--clock", "--begin", "--end", "--target-cpu", "--proc", "--memlimit",
                            "--ithread", "--xthread"})) {
            o.params += "," + name + "=" + value(next(args));
        } else if (is(arg, {"--all", "--live", "--nobatch", "--nofree", "--nostop", "--record-cpu", "--sched", "--tlab", "--ttsp"})) {
            o.params += "," + name;
        } else if (arg == "--all-user") {
            o.params += ",alluser";
        } else if (arg == "--ratelimit") {
            o.params += ",ratelimit=" + replace(list(next(args)), ",", ";");
        } else if (is(arg, {"--jfrsync", "--jfropts"})) {
            o.params += "," + name + "=" + value(next(args));
            o.output = "jfr";
        } else if (is(arg, {"--timeout", "--loop"})) {
            o.params += "," + name + "=" + value(next(args));
            if (arg == "--timeout") o.timeout = true;
            if (o.action == "collect") o.action = "start";
        } else if (arg == "--libpath") {
            o.libpath = next(args);
        } else if (arg == "--fdtransfer") {
            o.fdtransfer = brokerPipeName();
            o.params += ",fdtransfer=" + *o.fdtransfer;
        } else if (arg == "--probe") {
            o.params += ",event=" + value(next(args));
        } else if (arg == "--java") {
            o.java = next(args);
        } else if (arg == "--") {
            if (o.action != "launch") fail("Unrecognized option: " + arg);
            o.arguments.assign(args.begin(), args.end());
            args.clear();
        } else if (!arg.empty() && digit(arg[0]) && o.pid == 0) {
            o.pid = parsePid(arg);
        } else if (arg == "jps" && o.pid == 0) {
            o.pid = lookup.newest();
        } else if (!startsWith(arg, "-") && args.empty() && o.pid == 0) {
            // The last argument is the application name as it would appear in the jps tool
            o.pid = lookup.named(arg);
        } else {
            fail("Unrecognized option: " + arg);
        }
    }
    if (o.jattach) o.arguments.assign(args.begin(), args.end());
    return o;
}

bool isUrl(const std::string& file) {
    return startsWith(file, "http://") || startsWith(file, "https://");
}

bool jfrOutput(const Options& o, const std::string& file) {
    std::optional<std::string> output;
    auto arguments = o.output + o.format + o.params;
    for (size_t start = 0; start <= arguments.size();) {
        auto end = arguments.find(',', start);
        if (end == std::string::npos) end = arguments.size();
        auto argument = arguments.substr(start, end - start);
        auto name = argument.substr(0, argument.find('='));
        if (name == "jfr" || name == "jfropts" || name == "jfrsync") output = "jfr";
        else if (is(name, {"collapsed", "flamegraph", "tree", "traces", "flat", "otlp"})) output = name;
        start = end + 1;
    }
    if (output) return *output == "jfr";
    if (isUrl(file)) return false;
    auto extension = file.rfind('.');
    return extension != std::string::npos && file.compare(extension, std::string::npos, ".jfr") == 0;
}
}
