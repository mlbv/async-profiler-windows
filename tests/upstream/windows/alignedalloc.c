/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * posix_memalign and aligned_alloc for test/native/libs/jnimalloc.c. The UCRT exports neither.
 * Blocks come from the CRT malloc, whose 16-byte alignment covers the requests the tests make,
 * so the caller releases them with free() as upstream does.
 */

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>

#define CRT_ALIGNMENT 16

static int supported(size_t alignment) {
    return alignment >= sizeof(void*) && (alignment & (alignment - 1)) == 0 && alignment <= CRT_ALIGNMENT;
}

__declspec(dllexport) int posix_memalign(void** result, size_t alignment, size_t size) {
    if (!supported(alignment)) {
        return EINVAL;
    }
    void* ptr = malloc(size);
    if (ptr == NULL) {
        return ENOMEM;
    }
    *result = ptr;
    return 0;
}

__declspec(dllexport) void* aligned_alloc(size_t alignment, size_t size) {
    if (!supported(alignment) || size % alignment != 0) {
        errno = EINVAL;
        return NULL;
    }
    return malloc(size);
}
