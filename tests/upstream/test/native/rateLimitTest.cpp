/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */

#include <limits.h>
#include "rateLimit.h"
#include "testRunner.hpp"

TEST_CASE(Rate_limit_maximum_carryover) {
    Arguments args;
    args._rate_limit[EC_CPU] = INT_MAX;
    RateLimit::enable(args);
    RateLimit::refill();
    CHECK_EQ(RateLimit::allow(EXECUTION_SAMPLE), true);
    RateLimit::disable();
}
