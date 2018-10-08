// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)


#ifndef __RMC_COMMON_H__
#define __RMC_COMMON_H__

#include <stdint.h>

// TODO: Split up into multiple files. Some available as library
// headers, some as included by code that uses this library.

// TODO: Rename externally accessible structs and functions
//       rmc_xxx
//
typedef uint64_t packet_id_t;
typedef uint16_t payload_len_t;
typedef uint64_t usec_timestamp_t;

typedef struct list {
    struct list_node* head; 
    struct list_node* tail; 
    uint32_t elem_count;
} list_t;

typedef union list_data {
    void* data;
    packet_id_t pid;
} list_data_t;

#define LIST_DATA(_data) ({ list_data_t dt = { .data = _data}; dt;})
#define LIST_PID(_pid) ({ list_data_t dt = { .pid = _pid}; dt;})

typedef struct list_node { 
    list_data_t data;
    struct list_node* next; 
    struct list_node* prev; 
    list_t* list;
} list_node_t;

extern void list_init(list_t* list);

extern uint32_t list_size(list_t* list);

extern list_node_t* list_head(list_t* list);
extern list_node_t* list_tail(list_t* list);


extern list_node_t* list_prev(list_node_t* node);
extern list_node_t* list_next(list_node_t* node);

extern list_node_t* list_push_head(list_t* list, list_data_t data);
extern list_node_t* list_push_head_node(list_t* list, list_node_t* node) ;

extern list_node_t* list_push_tail(list_t* list, list_data_t data);
extern list_node_t* list_push_tail_node(list_t* list, list_node_t* node) ;

extern list_node_t* list_insert_before_node(list_node_t* prev, list_node_t* data);
extern list_node_t* list_insert_before(list_node_t* prev, list_data_t data);

extern list_node_t* list_insert_after_node(list_node_t* prev, list_node_t* data);
extern list_node_t* list_insert_after(list_node_t* prev, list_data_t data);

extern list_node_t* list_unlink(list_node_t* node);
extern void list_delete(list_node_t* node);

extern list_data_t list_pop_head(list_t* list);
extern list_node_t* list_pop_head_node(list_t* list);
extern list_data_t list_pop_tail(list_t* list);
extern list_node_t* list_pop_tail_node(list_t* list);

extern void list_for_each(list_t* list,
                          uint8_t (*func)(list_node_t*node, void* user_data),
                          void*);
// Sorted on descending PID for quick insertion
extern list_node_t* list_insert_sorted(list_t* list,
                                       list_data_t new_elem,
                                       int (*compare_func)(list_data_t new_elem,
                                                           list_data_t existing_elem));

extern list_node_t* list_insert_sorted_node(list_t* list,
                                            list_node_t* node,
                                            int (*compare_func)(list_data_t new_elem,
                                                                list_data_t existing_elem));

typedef struct packet_interval {
    packet_id_t first_pid; // First packet ID in interval
    packet_id_t last_pid; // LAst packet ID in interval
} packet_interval_t;

// Used for iterators etc.
#define lambda(return_type, function_body) \
    ({                                     \
        return_type __fn__ function_body   \
            __fn__;                        \
    })

extern uint32_t get_packet_intervals(list_t* packets,
                                     uint32_t max_packet_count,
                                     list_t* result_intervals);

extern usec_timestamp_t rmc_usec_monotonic_timestamp(void);

#ifdef INCLUDE_TEST
extern void test_packet_interval();
extern void test_packet_intervals();
extern void test_list();
extern void test_dump_list(list_t* list);
extern void test_pub(void);
#endif

#endif // __RMC_COMMON_H__
