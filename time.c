// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)


#include "rmc_internal.h"

#include <time.h>
#include <bits/time.h>

usec_timestamp_t rmc_usec_monotonic_timestamp(void)
{
    struct timespec res;

    clock_gettime(CLOCK_BOOTTIME, &res);

    return (usec_timestamp_t) res.tv_sec * 1000000 + res.tv_nsec / 1000;
}
