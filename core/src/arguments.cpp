/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#include <limits.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include "arguments.h"
#include "os.h"
#ifdef _WIN32
#include "log.h"
#endif


// Arguments of the last start/resume command; reused for shutdown and restart
Arguments _global_args;

// Predefined value that denotes successful operation
const Error Error::OK(NULL);

// Statically compute hash code of a string containing up to 12 [a-z] letters
#define HASH(s)  ((s[0] & 31LL)       | (s[1] & 31LL) <<  5 | (s[2]  & 31LL) << 10 | (s[3]  & 31LL) << 15 | \
                  (s[4] & 31LL) << 20 | (s[5] & 31LL) << 25 | (s[6]  & 31LL) << 30 | (s[7]  & 31LL) << 35 | \
                  (s[8] & 31LL) << 40 | (s[9] & 31LL) << 45 | (s[10] & 31LL) << 50 | (s[11] & 31LL) << 55)

// Simulate switch statement over string hashes
#define SWITCH(arg)    long long arg_hash = hash(arg); if (0)

#define CASE(s)        } else if (arg_hash == HASH(s "            ")) {

#define DEFAULT()      } else {


// Parses agent arguments.
// The format of the string is: arg[,arg...]
Error Arguments::parse(const char* args) {
    if (args == NULL) {
        return Error::OK;
    }

    size_t len = strlen(args);
    free(_buf);
    _buf = (char*)malloc(len + 1);
    if (_buf == NULL) {
        return Error("Not enough memory to parse arguments");
    }
    char* args_copy = strcpy(_buf, args);

    const char* msg = NULL;

    for (char* arg = strtok(args_copy, ","); arg != NULL; arg = strtok(NULL, ",")) {
        char* value = strchr(arg, '=');
        if (value != NULL) *value++ = 0;

        SWITCH (arg) {
            // Actions
            CASE("start")
                _action = ACTION_START;

            CASE("resume")
                _action = ACTION_RESUME;

            CASE("stop")
                _action = ACTION_STOP;

            CASE("dump")
                _action = ACTION_DUMP;

            CASE("status")
                _action = ACTION_STATUS;

            CASE("metrics")
                _action = ACTION_METRICS;

            CASE("list")
                _action = ACTION_LIST;

            CASE("version")
                _action = ACTION_VERSION;

#ifdef _WIN32
            CASE("resolve")
                _action = ACTION_RESOLVE;
#endif

            // Output formats
            CASE("collapsed")
                _output = OUTPUT_COLLAPSED;

            CASE("flamegraph")
                _output = OUTPUT_FLAMEGRAPH;

            CASE("tree")
                _output = OUTPUT_TREE;

            CASE("jfr")
                _output = OUTPUT_JFR;

            CASE("jfropts")
                _output = OUTPUT_JFR;
                if (value == NULL) {
                    msg = "Invalid jfropts";
                } else if (value[0] >= '0' && value[0] <= '9') {
                    _jfr_options = (int)strtol(value, NULL, 0);
                } else if (strstr(value, "mem")) {
                    _jfr_options |= IN_MEMORY;
                }

            CASE("jfrsync")
                _output = OUTPUT_JFR;
                _jfr_options |= JFR_SYNC_OPTS;
                _jfr_sync = value == NULL ? "default" : value;

            CASE("traces")
                _output = OUTPUT_TEXT;
                _dump_traces = value == NULL ? INT_MAX : atoi(value);

            CASE("flat")
                _output = OUTPUT_TEXT;
                _dump_flat = value == NULL ? INT_MAX : atoi(value);

            CASE("otlp")
                _output = OUTPUT_OTLP;

            CASE("samples")
                _counter = COUNTER_SAMPLES;

            CASE("total")
                _counter = COUNTER_TOTAL;

            CASE("ratelimit")
                if (value == NULL || !parseRateLimit(value)) {
                    msg = "Invalid ratelimit";
                }

            CASE("chunksize")
                if (value == NULL || (_chunk_size = parseUnits(value, BYTES)) < 0) {
                    msg = "Invalid chunksize";
                }

            CASE("chunktime")
                if (value == NULL || (_chunk_time = parseUnits(value, SECONDS)) < 0) {
                    msg = "Invalid chunktime";
                }

            // Basic options
            CASE("event")
                if (value == NULL || value[0] == 0) {
                    msg = "event must not be empty";
                } else if (strcmp(value, EVENT_ALLOC) == 0) {
                    if (_alloc < 0) _alloc = 0;
                } else if (strcmp(value, EVENT_NATIVEMEM) == 0) {
                    if (_nativemem < 0) _nativemem = 0;
                } else if (strcmp(value, EVENT_LOCK) == 0) {
                    if (_lock < 0) _lock = DEFAULT_LOCK_INTERVAL;
                } else if (strcmp(value, EVENT_NATIVELOCK) == 0) {
                    if (_nativelock < 0) _nativelock = DEFAULT_LOCK_INTERVAL;
                } else if (_event != NULL && !_all) {
                    msg = "Duplicate event argument";
                } else {
                    _event = value;
                }

            CASE("timeout")
                if (value == NULL || (_timeout = parseTimeout(value)) == -1) {
                    msg = "Invalid timeout";
                }

            CASE("loop")
                if (value == NULL || (_loop = parseTimeout(value)) == -1) {
                    msg = "Invalid loop duration";
                }

            CASE("memlimit")
                {
                    int64_t limit = value == NULL ? 0 : parseUnits(value, BYTES);
                    if (limit < 0) msg = "Invalid memory limit";
                    else _mem_limit = static_cast<size_t>(limit);
                }

            CASE("alloc")
                _alloc = value == NULL ? 0 : parseUnits(value, BYTES);

            CASE("tlab")
                _tlab = true;

            CASE("nativemem")
                _nativemem = value == NULL ? 0 : parseUnits(value, BYTES);

            CASE("nofree")
                _nofree = true;

            CASE("trace")
                _trace.push_back(value);

            CASE("lock")
                _lock = value == NULL ? DEFAULT_LOCK_INTERVAL : parseUnits(value, NANOS);

            CASE("nativelock")
                _nativelock = value == NULL ? DEFAULT_LOCK_INTERVAL : parseUnits(value, NANOS);

            CASE("wall")
                _wall = value == NULL ? 0 : parseUnits(value, NANOS);

            CASE("proc")
                _proc = value == NULL ? DEFAULT_PROC_INTERVAL : parseUnits(value, SECONDS);

            CASE("cpu")
                if (_event != NULL) {
                    msg = "Duplicate event argument";
                } else {
                    _event = EVENT_CPU;
                }

            CASE("all")
                _all = true;
                _live = true;
                if (_wall < 0) {
                    _wall = 0;
                }
                if (_alloc < 0) {
                    _alloc = 0;
                }
                if (_lock < 0) {
                    _lock = DEFAULT_LOCK_INTERVAL;
                }
                if (_nativelock < 0) {
                    _nativelock = DEFAULT_LOCK_INTERVAL;
                }
                if (_nativemem < 0) {
                    _nativemem = DEFAULT_ALLOC_INTERVAL;
                }

                if (_proc < 0 && (OS::isLinux() || OS::isWindows())) {
                    _proc = DEFAULT_PROC_INTERVAL;
                }

                if (_event == NULL && (OS::isLinux() || OS::isWindows())) {
                    _event = EVENT_CPU;
                }

            CASE("interval")
                if (value == NULL || (_interval = parseUnits(value, UNIVERSAL)) <= 0) {
                    msg = "Invalid interval";
                }

            CASE("jstackdepth")
                if (value == NULL || (_jstackdepth = atoi(value)) <= 0) {
                    msg = "jstackdepth must be > 0";
                } else {
                    char* slash = strchr(value, '/');
                    _truncated_stack_depth = slash != NULL ? atoi(slash + 1) : _jstackdepth;
                }

            CASE("signal")
                {
                    auto component = [](const char*& text) {
                        if (text == NULL || *text < '0' || *text > '9') return -1;
                        int number = 0;
                        do {
                            number = number * 10 + (*text++ - '0');
                            if (number > 255) return -1;
                        } while (*text >= '0' && *text <= '9');
                        return number > 0 ? number : -1;
                    };
                    const char* cursor = value;
                    int cpu = component(cursor);
                    int wall = 0;
                    if (cpu > 0 && *cursor == '/') {
                        ++cursor;
                        wall = component(cursor);
                    }
                    if (cpu < 0 || wall < 0 || *cursor != 0) {
                        msg = "signal must be in the range 1..255, optionally CPU/WALL";
                    } else {
                        _signal = cpu | (wall << 8);
                    }
                }

            CASE("features")
                if (value != NULL) {
                    if (strstr(value, "stats"))    _features.stats = 1;
                    if (strstr(value, "jnienv"))   _features.jnienv = 1;
                    if (strstr(value, "agct"))     _features.agct = 1;
                    if (strstr(value, "mixed"))    _features.mixed = 1;
                    if (strstr(value, "vtable"))   _features.vtable_target = 1;
                    if (strstr(value, "comptask")) _features.comp_task = 1;
                    if (strstr(value, "pcaddr"))   _features.pc_addr = 1;
                }

            CASE("file")
                if (value == NULL || value[0] == 0) {
                    msg = "file must not be empty";
                }
                _file = value;

#ifdef _WIN32
            CASE("filebase")
                if (value == NULL || value[0] == 0) msg = "filebase must not be empty";
                _filebase = value;

            CASE("fileresult")
                if (value == NULL || value[0] == 0) msg = "fileresult must not be empty";
                _fileresult = value;
#endif

            CASE("log")
                _log = value == NULL || value[0] == 0 ? NULL : value;

            CASE("loglevel")
                if (value == NULL || value[0] == 0) {
                    msg = "loglevel must not be empty";
                }
                _loglevel = value;

            CASE("quiet")
                _quiet = true;

            CASE("fdtransfer")
                _fdtransfer = true;
#ifdef _WIN32
                if (value != NULL && value[0] == 0) {
#else
                if (value == NULL || value[0] == 0) {
#endif
                    msg = "fdtransfer path must not be empty";
                }
                _fdtransfer_path = value;

            // Filters
            CASE("filter")
                _filter_enabled = true;
                if (value != NULL && value[0] != 0) {
                    msg = "filter does not take a value; use ithread/xthread";
                }

            CASE("ithread")
                _filter_enabled = true;
                if (value == NULL) {
                    msg = "ithread requires a thread name pattern";
                } else {
                    _threads_include.push_back(value);
                }

            CASE("xthread")
                _filter_enabled = true;
                if (value == NULL) {
                    msg = "xthread requires a thread name pattern";
                } else {
                    _threads_exclude.push_back(value);
                }

            CASE("include")
                _include.push_back(value);

            CASE("exclude")
                _exclude.push_back(value);

            CASE("threads")
                _threads = true;

            CASE("sched")
                _sched = true;

            CASE("record-cpu")
                _record_cpu = true;

            CASE("live")
                _live = true;

            CASE("nobatch")
                _nobatch = true;

            CASE("alluser")
                _alluser = true;

            CASE("cstack")
                if (value != NULL) {
                    if (strcmp(value, "fp") == 0) {
                        _cstack = CSTACK_FP;
                    } else if (strcmp(value, "dwarf") == 0) {
                        _cstack = CSTACK_DWARF;
                    } else if (strcmp(value, "vm") == 0) {
                        _cstack = CSTACK_VM;
                    } else if (strcmp(value, "vmx") == 0) {
                        // cstack=vmx is a shorthand for cstack=vm,features=mixed
                        _cstack = CSTACK_VM;
                        _features.mixed = 1;
                    } else {
                        _cstack = CSTACK_NO;
                    }
                }

            CASE("clock")
                if (value != NULL) {
                    if (value[0] == 't') {
                        _clock = CLK_TSC;
                    } else if (value[0] == 'm') {
                        _clock = CLK_MONOTONIC;
                    }
                }

            CASE("target-cpu")
#ifdef _WIN32
                if (value == NULL || value[0] == 0) {
                    msg = "target-cpu requires an integer index";
                } else {
                    char* end;
                    errno = 0;
                    long cpu = strtol(value, &end, 10);
                    if (errno == ERANGE || end == value || *end != 0 || cpu < -1 || cpu > INT_MAX) {
                        msg = "target-cpu must be -1 or a nonnegative integer index";
                    } else {
                        _target_cpu = static_cast<int>(cpu);
                    }
                }
#else
                if (value == NULL || (_target_cpu = atoi(value)) < 0) {
                    _target_cpu = -1;
                }
#endif

            // Output style modifiers
            CASE("simple")
                _style |= STYLE_SIMPLE;

            CASE("dot")
                _style |= STYLE_DOTTED;

            CASE("norm")
                _style |= STYLE_NORMALIZE;

            CASE("sig")
                _style |= STYLE_SIGNATURES;

            CASE("ann")
                _style |= STYLE_ANNOTATE;

            CASE("lib")
                _style |= STYLE_LIB_NAMES;

            CASE("mcache")
                _mcache = value == NULL ? 1 : (unsigned char)strtol(value, NULL, 0);

            CASE("begin")
                _begin = value;

            CASE("end")
                _end = value;

            CASE("nostop")
                _nostop = true;

            CASE("ttsp")
                if (_begin != NULL || _end != NULL) {
                    msg = "begin and end must both be empty when ttsp is set";
                }
                _begin = "SafepointSynchronize::begin";
                _end = "RuntimeService::record_safepoint_synchronized";

            // FlameGraph options
            CASE("title")
                _title = value;

            CASE("minwidth")
                if (value != NULL) _minwidth = atof(value);

            CASE("reverse")
                _reverse = true;

            CASE("inverted")
                _inverted = true;

            DEFAULT()
                if (_unknown_arg == NULL) _unknown_arg = arg;
        }
    }

    // Return error only after parsing all arguments, when 'log' is already set
    if (msg != NULL) {
        return Error(msg);
    }

    if (_event == NULL && _alloc < 0 && _lock < 0 && _wall < 0 && _nativemem < 0 && _nativelock < 0 && _trace.empty()) {
        _event = EVENT_CPU;
    }

    if (_file != NULL && _output == OUTPUT_NONE && _action != ACTION_RESOLVE) {
        _output = detectOutputFormat(_file);
        _dump_traces = 100;
        _dump_flat = 200;
    }

    if (_action == ACTION_NONE && _output != OUTPUT_NONE) {
        _action = ACTION_DUMP;
    }

    return Error::OK;
}

const char* Arguments::file() {
#ifdef _WIN32
    _file_error = NULL;
#endif
    if (_file == NULL) return NULL;
    const char* expanded = strchr(_file, '%') != NULL ? expandFilePattern(_file) : _file;
#ifdef _WIN32
    if (_file_error != NULL) return "";
    if (_filebase != NULL && !isUrl(expanded)) {
        _expanded_file = WindowsProfiler::outputPath(expanded, _filebase);
        if (_expanded_file.empty()) _file_error = "Cannot resolve output path";
        return _expanded_file.c_str();
    }
#endif
    return expanded;
}

#ifdef _WIN32
int Arguments::openOutputFile(const char* filename, int flags) {
    if (_file_error != NULL) { errno = ENOENT; return -1; }
    if (_filebase != NULL && !WindowsProfiler::createOutputParents(filename)) return -1;
    int fd = asprof_open(filename, flags, 0644);
    if (fd >= 0 && !reportOutputFile(filename)) {
        int error = errno;
        close(fd);
        errno = error;
        return -1;
    }
    return fd;
}

bool Arguments::reportOutputFile(const char* filename) {
    return _output_files->report(_fileresult, filename);
}

bool Arguments::reportOutputError(const char* message) {
    return _output_files->reportError(_fileresult, message);
}
#endif

// Returns true if the log file is a temporary file of asprof launcher
bool Arguments::hasTemporaryLog() const {
#ifdef _WIN32
    if (_log == NULL) return false;
    const char* name = strrchr(_log, '\\');
    const char* slash = strrchr(_log, '/');
    if (slash != NULL && (name == NULL || slash > name)) name = slash;
    return strncmp(name == NULL ? _log : name + 1, "asprof-log.", 11) == 0;
#else
    return _log != NULL && strncmp(_log, "/tmp/asprof-log.", 16) == 0;
#endif
}

// Should match statically computed HASH(arg)
long long Arguments::hash(const char* arg) {
    long long h = 0;
    for (int shift = 0; *arg != 0; shift += 5) {
        h |= (*arg++ & 31LL) << shift;
    }
    return h;
}

// Expands the following patterns:
//   %p       process id
//   %t       timestamp (yyyyMMdd-hhmmss)
//   %n{MAX}  sequence number
//   %{ENV}   environment variable
const char* Arguments::expandFilePattern(const char* pattern) {
    _expanded_file.clear();

    while (*pattern != 0) {
        char c = *pattern++;
        if (c == '%') {
            char value[32];
            c = *pattern++;
            if (c == 0) {
                break;
            } else if (c == 'p') {
                snprintf(value, sizeof(value), "%d", getpid());
                _expanded_file += value;
                continue;
            } else if (c == 't') {
                time_t timestamp = time(NULL);
                struct tm t;
                localtime_r(&timestamp, &t);
                snprintf(value, sizeof(value), "%d%02d%02d-%02d%02d%02d",
                                t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
                                t.tm_hour, t.tm_min, t.tm_sec);
                _expanded_file += value;
                continue;
            } else if (c == 'n') {
                unsigned int max_files = 0;
                const char* p;
                if (*pattern == '{' && (p = strchr(pattern, '}')) != NULL) {
                    max_files = atoi(pattern + 1);
                    pattern = p + 1;
                }
                snprintf(value, sizeof(value), "%u", max_files > 0 ? _file_num % max_files : _file_num);
                _expanded_file += value;
                continue;
            } else if (c == '{') {
                const char* p = strchr(pattern, '}');
                if (p != NULL) {
                    std::string env_key(pattern, p - pattern);
#ifdef _WIN32
                    std::string env_value;
                    auto result = WindowsProfiler::environmentValue(env_key, env_value);
                    if (result != WindowsProfiler::EnvironmentResult::Value) {
                        _file_error = result == WindowsProfiler::EnvironmentResult::Missing
                                ? "Output environment variable is not defined" : "Cannot read output environment variable";
                        Log::error(result == WindowsProfiler::EnvironmentResult::Missing
                                ? "Output environment variable '%s' is not defined"
                                : "Cannot read output environment variable '%s'", env_key.c_str());
                        return "";
                    }
                    _expanded_file += env_value;
                    pattern = p + 1;
                    continue;
#else
                    const char* env_value = getenv(env_key.c_str());
                    if (env_value != NULL) {
                        _expanded_file += env_value;
                        pattern = p + 1;
                        continue;
                    }
#endif
                }
            } else if (c != '%') {
                _expanded_file += '%';  // keep other escape sequences (e.g. URL encoding) intact
            }
        }
        _expanded_file += c;
    }

    return _expanded_file.c_str();
}

Output Arguments::detectOutputFormat(const char* file) {
    if (isUrl(file)) {
        return OUTPUT_OTLP;
    }

    const char* ext = strrchr(file, '.');
    if (ext != NULL) {
        if (strcmp(ext, ".html") == 0) {
            return OUTPUT_FLAMEGRAPH;
        } else if (strcmp(ext, ".jfr") == 0) {
            return OUTPUT_JFR;
        } else if (strcmp(ext, ".collapsed") == 0 || strcmp(ext, ".folded") == 0) {
            return OUTPUT_COLLAPSED;
        }
    }
    return OUTPUT_TEXT;
}

bool Arguments::isUrl(const char* file) {
    return strncmp(file, "http://", 7) == 0 || strncmp(file, "https://", 8) == 0;
}

int64_t Arguments::parseUnits(const char* str, const Multiplier* multipliers) {
    char* end;
    errno = 0;
    int64_t result = strtoll(str, &end, 0);
    if (end == str || errno == ERANGE || result < 0) {
        return -1;
    }

    char c = *end;
    if (c == 0) {
        return result;
    }
    if (c >= 'A' && c <= 'Z') {
        c += 'a' - 'A';
    }

    for (const Multiplier* m = multipliers; m->symbol; m++) {
        if (c == m->symbol) {
            return result > INT64_MAX / m->multiplier ? -1 : result * m->multiplier;
        }
    }

    return -1;
}

int Arguments::parseTimeout(const char* str) {
    const char* p = strchr(str, ':');
    if (p == NULL) {
        return parseUnits(str, SECONDS);
    }

    int hh = str[0] >= '0' && str[0] <= '2' ? atoi(str) : 0xff;
    int mm = p[1] >= '0' && p[1] <= '5' ? atoi(p + 1) : 0xff;
    int ss = (p = strchr(p + 1, ':')) != NULL && p[1] >= '0' && p[1] <= '5' ? atoi(p + 1) : 0xff;
    return 0xff000000 | hh << 16 | mm << 8 | ss;
}

bool Arguments::parseRateLimit(char* str) {
    static constexpr char CATEGORY_NAMES[] = "0:cpu,1:alloc,2:lock,3:wall,4:nativemem,5:nativelock,6:trace,7:span";

    while (*str != 0) {
        char* value = strchr(str, ':');
        if (value == NULL) {
            return false;
        }
        *value++ = 0;

        const char* c = strstr(CATEGORY_NAMES + 2, str);
        if (c == NULL || c[-1] != ':' || c[strlen(str)] > ',') {
            return false;
        }
        int category = c[-2] - '0';

        int64_t limit = strtoll(value, &str, 10);
        if (limit < 0 || limit > INT_MAX || str == value || *str > ';') {
            return false;
        }
        if (*str) str++;

        _rate_limit[category] = limit;
    }
    return true;
}

Arguments::~Arguments() {
    if (!_shared) free(_buf);
}

void Arguments::save() {
    if (this != &_global_args) {
        free(_global_args._buf);
        _global_args = *this;
        _shared = true;
    }
}
