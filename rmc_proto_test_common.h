// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#ifndef __RMC_PROTO_TEST_COMMON_H__
#define __RMC_PROTO_TEST_COMMON_H__

#include "rmc_proto.h"
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

typedef struct {
    char* payload;
    packet_id_t pid;
    uint32_t msec_wait;
} rmc_test_data_t;

extern char* _index(rmc_connection_index_t index, char* res);


extern int _descriptor(rmc_context_t* ctx,
                       rmc_connection_index_t index);

extern void* _test_proto_alloc(payload_len_t plen);

extern void test_proto_free(void* payload, payload_len_t plen);

extern void _test(char* fmt_string, int major, int minor, int error);

extern void poll_add(rmc_context_t* ctx,
                     int descriptor,
                     rmc_connection_index_t index,
                     rmc_poll_action_t action);

extern void poll_modify(rmc_context_t* ctx,
                        int descriptor,
                        rmc_connection_index_t index,
                        rmc_poll_action_t old_action,
                        rmc_poll_action_t new_action);

extern void poll_remove(rmc_context_t* ctx,
                        int descriptor,
                        rmc_connection_index_t index);

extern int process_packet(rmc_context_t* ctx, int major, int minor);

extern void queue_test_data(rmc_context_t* ctx, rmc_test_data_t* td_arr, int td_arr_ind);

extern int process_events(rmc_context_t* ctx, int epollfd, usec_timestamp_t timeout, int major);

#endif // __RMC_PROTO_TEST_COMMON_H__
