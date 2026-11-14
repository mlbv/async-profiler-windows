/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Derived from upstream test/test/nativelock/native_lock_contention.c; modified for Windows x86-64.
 */

// Windows variant of native_lock_contention.c: the mutex and reader/writer lock are a critical
// section and an SRW lock, the primitives the profiler's nativelock engine traces on Windows.

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <windows.h>

static CRITICAL_SECTION test_mutex;
static SRWLOCK test_rwlock = SRWLOCK_INIT;

void* mutex_contention_thread(void* arg) {
    for (int i = 0; i < 50; i++) {
        EnterCriticalSection(&test_mutex);
        usleep(5000);
        LeaveCriticalSection(&test_mutex);
        usleep(1000);
    }
    return NULL;
}

void* rwlock_reader_thread(void* arg) {
    for (int i = 0; i < 30; i++) {
        AcquireSRWLockShared(&test_rwlock);
        usleep(3000);
        ReleaseSRWLockShared(&test_rwlock);
        usleep(1000);
    }
    return NULL;
}

void* rwlock_writer_thread(void* arg) {
    for (int i = 0; i < 15; i++) {
        AcquireSRWLockExclusive(&test_rwlock);
        usleep(5000);
        ReleaseSRWLockExclusive(&test_rwlock);
        usleep(2000);
    }
    return NULL;
}

int main(int argc, char* argv[]) {
    InitializeCriticalSection(&test_mutex);

    printf("Testing all lock types...\n");
    printf("Testing mutex contention...\n");
    const int mutex_threads = 4;
    pthread_t mutex_thread_array[mutex_threads];

    for (int i = 0; i < mutex_threads; i++) {
        pthread_create(&mutex_thread_array[i], NULL, mutex_contention_thread, NULL);
    }

    for (int i = 0; i < mutex_threads; i++) {
        pthread_join(mutex_thread_array[i], NULL);
    }

    printf("Testing rwlock contention...\n");
    const int num_readers = 4;
    const int num_writers = 2;
    pthread_t rwlock_threads[num_readers + num_writers];

    for (int i = 0; i < num_readers; i++) {
        pthread_create(&rwlock_threads[i], NULL, rwlock_reader_thread, NULL);
    }

    for (int i = 0; i < num_writers; i++) {
        pthread_create(&rwlock_threads[num_readers + i], NULL, rwlock_writer_thread, NULL);
    }

    for (int i = 0; i < num_readers + num_writers; i++) {
        pthread_join(rwlock_threads[i], NULL);
    }

    fprintf(stderr, "Test completed successfully.\n");
    return 0;
}
