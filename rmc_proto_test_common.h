// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#ifndef __RMC_PROTO_TEST_COMMON_H__
#define __RMC_PROTO_TEST_COMMON_H__

#include "reliable_multicast.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

typedef struct  __attribute__((packed))
signal {
    uint32_t node_id;         // 4
    uint32_t signal_id;       // 4
    uint32_t max_signal_id;   // 4
    uint64_t filler;          // 8
} signal_t;                   // 20 bytes.

extern void* _test_proto_alloc(payload_len_t plen);

extern void test_proto_free(void* payload, payload_len_t plen);

extern void _test(char* fmt_string, int major, int minor, int error);

extern void poll_add(user_data_t user_data,
                     int descriptor,
                     rmc_index_t index,
                     rmc_poll_action_t action);

extern void poll_modify(user_data_t user_data,
                        int descriptor,
                        rmc_index_t index,
                        rmc_poll_action_t old_action,
                        rmc_poll_action_t new_action);

extern void poll_remove(user_data_t user_data,
                        int descriptor,
                        rmc_index_t index);



extern char* _op_res_string(uint8_t res);
#endif // __RMC_PROTO_TEST_COMMON_H__
