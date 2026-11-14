/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#include <algorithm>
#include "rateLimit.h"

RateLimit::Budget RateLimit::_budget[EC_CATEGORIES];
int RateLimit::_enabled_categories = 0;

void RateLimit::enable(Arguments& args) {
    int enabled_categories = 0;
    for (int i = 0; i < EC_CATEGORIES; i++) {
        if (args._rate_limit[i] >= 0) {
            _budget[i].budget = _budget[i].limit = args._rate_limit[i];
            enabled_categories |= 1 << i;
        }
    }
    storeRelease(_enabled_categories, enabled_categories);
}

void RateLimit::disable() {
    storeRelease(_enabled_categories, 0);
}

void RateLimit::refill() {
    if (_enabled_categories == 0) return;

    for (int i = 0; i < EC_CATEGORIES; i++) {
        if (_enabled_categories & (1 << i)) {
            // Allow up to 100% budget carryover to account for short bursts
            int64_t carryover = std::min(std::max(_budget[i].budget, int64_t(0)), _budget[i].limit);
            storeRelease(_budget[i].budget, _budget[i].limit + carryover);
        }
    }
}
