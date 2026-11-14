/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#ifndef _ASPROF_THREAD_LOCAL_H
#define _ASPROF_THREAD_LOCAL_H

#include "asprof.h"
#include <pthread.h>

class ThreadLocalData {
  public:
#ifdef _WIN32
    static asprof_thread_local_data* getIfPresent();
    static asprof_thread_local_data* get();
#else
    // Get the `asprof_thread_local_data` or nullptr if not present.
    // This function *is* async-signal safe.
    static asprof_thread_local_data* getIfPresent()  {
        if (_profiler_data_key == -1) {
            return nullptr;
        }

        return (asprof_thread_local_data*) pthread_getspecific(_profiler_data_key);
    }

    // Get the `asprof_thread_local_data`. See the `asprof_get_thread_local_data` docs.
    static asprof_thread_local_data* get()  {
        if (_profiler_data_key == -1) {
            return nullptr;
        }

        asprof_thread_local_data* tld = (asprof_thread_local_data*) pthread_getspecific(_profiler_data_key);
        if (tld == nullptr) {
            return initThreadLocalData(_profiler_data_key);
        }
        return tld;
    }

  private:
    static asprof_thread_local_data* initThreadLocalData(pthread_key_t profiler_data_key);
    static pthread_key_t _profiler_data_key;
#endif
};

#endif // _ASPROF_THREAD_LOCAL_H
