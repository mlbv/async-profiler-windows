/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#include "asprof.h"
#include "hooks.h"
#include "httpClient.h"
#include "profiler.h"
#include "tsc.h"
#include "threadLocalData.h"
#include "userEvents.h"
#include "vmEntry.h"

static asprof_error_t asprof_error(const char* msg) {
    return (asprof_error_t)msg;
}


DLLEXPORT void asprof_init() {
    Hooks::init(true);
    VM::tryAttach();
}

DLLEXPORT const char* asprof_error_str(asprof_error_t err) {
    return err;
}

DLLEXPORT asprof_error_t asprof_execute(const char* command, asprof_writer_t output_callback) {
    Arguments args;
    Error error = args.parse(command);
    if (error) {
        return asprof_error(error.message());
    }

    Log::open(args);
    TemporaryLog log(args);

    const char* file = args.hasOutputFile() ? args.file() : NULL;
    if (file == NULL) {
        CallbackWriter out(output_callback);
        error = Profiler::instance()->runInternal(args, out);
    } else if (Arguments::isUrl(file)) {
        BufferWriter out;
        error = Profiler::instance()->runInternal(args, out);
        if (!error) {
            error = HttpClient::send(file, out.buf(), out.size(), args._output);
        }
    } else {
        error = Profiler::instance()->run(args);
    }

    return error ? asprof_error(error.message()) : NULL;
}

DLLEXPORT asprof_thread_local_data* asprof_get_thread_local_data(void) {
    return ThreadLocalData::get();
}

DLLEXPORT asprof_jfr_event_key asprof_register_jfr_event(const char* name) {
    return UserEvents::registerEvent(name);
}

DLLEXPORT asprof_error_t asprof_emit_jfr_event(asprof_jfr_event_key type, const uint8_t* data, size_t len) {
    if (type <= 0) return asprof_error("User-event key is invalid");
    if (data == NULL && len != 0) return asprof_error("User-event data is null");
    if (len > ASPROF_MAX_JFR_EVENT_LENGTH) {
        return asprof_error("User-event data exceeds 2048 bytes");
    }

    UserEvent event;
    event._start_time = TSC::ticks();
    event._type = type;
    event._data = data;
    event._len = len;
    if (Profiler::instance()->jfr()->active() && !Profiler::instance()->recordEventOnly(USER_EVENT, &event)) {
        return asprof_error("User-event buffer is busy; the event was not recorded");
    }
    return NULL;
}
