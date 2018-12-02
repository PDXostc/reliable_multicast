// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)


#ifndef __RMC_COMMON_H__
#define __RMC_COMMON_H__

#include <stdint.h>
#include "rmc_list.h"

// FIXME MEDIUM: Split up into multiple files. Some available as library
// headers, some as included by code that uses this library.

// FIXME LOW: Rename externally accessible structs and functions
//       rmc_xxx
//
typedef uint64_t packet_id_t;
typedef uint32_t rmc_context_id_t;

RMC_LIST(packet_id_list, packet_id_node, packet_id_t)

typedef packet_id_list packet_id_list_t;
typedef packet_id_node packet_id_node_t;

typedef uint16_t payload_len_t;
typedef int64_t usec_timestamp_t;

typedef union {
    void* ptr;
    uint32_t u32;
    int32_t i32;
    uint64_t u64;
    int64_t i64;
} user_data_t;

#define user_data_nil() ((user_data_t) { .u64 = 0 })
#define user_data_u64(_u64) ((user_data_t) { .u64 = _u64 })
#define user_data_i64(_i64) ((user_data_t) { .i64 = _i64 })
#define user_data_u32(_u32) ((user_data_t) { .u32 = _u32 })
#define user_data_i32(_i32) ((user_data_t) { .i32 = _i32 })
#define user_data_ptr(_ptr) ((user_data_t) { .ptr = _ptr })

// Used for iterators etc.
#define lambda(return_type, function_body) \
    ({                                     \
        return_type __fn__ function_body   \
            __fn__;                        \
    })


extern usec_timestamp_t rmc_usec_monotonic_timestamp(void);

#endif // __RMC_COMMON_H__
