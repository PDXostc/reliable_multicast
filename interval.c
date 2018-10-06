// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)


#include "rmc_common.h"
#include <assert.h>
#include <stdlib.h>

#ifdef INCLUDE_TEST
#include <stdio.h>
#endif

// TODO: Ditch malloc and use a stack-based alloc/free setup that operates
//       on static-sized heap memory allocated at startup. 
static packet_interval_t* _alloc_interval(void)
{
    packet_interval_t* res = (packet_interval_t*) malloc(sizeof(packet_interval_t));
    assert(res);

    return res;
}

static void _free_interval(packet_interval_t* node)
{
    assert(node);
    free((void*) node);
}

// Find a consecutive sequence of packet IDs in the packet id-sorted
// list starting with node 'start'.  Return the first node after the
// consecutive sequence was broken by a hole.  Return 0 reached end of
// list
list_node_t* get_packet_interval(list_node_t* start, packet_interval_t* interval)
{
    packet_id_t first_pid = start->data.pid;
    packet_id_t last_pid = start->data.pid;

    while(start) {
        // Are we past the first iteration and did we find a hole?
        if (first_pid != last_pid &&
            start->data.pid != last_pid) 
            break;

        last_pid++;
        start = list_next(start);
    }    
    last_pid--;
    interval->first_pid = first_pid;
    interval->last_pid = last_pid;
    return start;
}

//
// Find all consecutive intervals in the packet id-sorted list
// 'packets'. Imnser
// 
uint32_t get_packet_intervals(list_t* packets,
                              uint32_t max_packet_count,
                              list_t* result_intervals)
{
    uint32_t res = 0;
    list_node_t* node = 0;
    assert(packets);
    
    if (packets->elem_count == 0)
        return 0;

    node = list_head(packets);

    while(node) {
        packet_interval_t* interval = _alloc_interval();
        assert(interval);

        node = get_packet_interval(node, interval);
        list_push_tail(result_intervals, LIST_DATA(interval));
        res += interval->last_pid - interval->first_pid + 1;
    }

    return res;
}

//  1 [1-1]
//  3 [1-1] [3-3]
//  3 [1-3]
#ifdef INCLUDE_TEST
void test_packet_interval()
{
    list_t p1;
    list_node_t* node;
    packet_interval_t intv = { .first_pid = 0, .last_pid = 0 };

    list_init(&p1);
    list_push_tail(&p1, LIST_PID(1));
    list_push_tail(&p1, LIST_PID(2));
    list_push_tail(&p1, LIST_PID(3));
    list_push_tail(&p1, LIST_PID(4));
    list_push_tail(&p1, LIST_PID(5));

    list_push_tail(&p1, LIST_PID(7));
    list_push_tail(&p1, LIST_PID(8));
    list_push_tail(&p1, LIST_PID(9));

    list_push_tail(&p1, LIST_PID(223));
    list_push_tail(&p1, LIST_PID(224));

    list_push_tail(&p1, LIST_PID(226));

    node = list_head(&p1);

    node = get_packet_interval(node, &intv);
    if (intv.first_pid != 1 || intv.last_pid != 5) {
        printf("Failed interval test 1.1. Wanted 1:5. Got %lu:%lu\n",
               intv.first_pid, intv.last_pid);
        exit(0);
    }

    intv.first_pid = 0;
    intv.last_pid = 0;
    node = get_packet_interval(node, &intv);
    if (intv.first_pid != 7 || intv.last_pid != 9) {
        printf("Failed interval test 1.2. Wanted 7:9. Got %lu:%lu\n",
               intv.first_pid, intv.last_pid);
        exit(0);
    }

    intv.first_pid = 0;
    intv.last_pid = 0;
    node = get_packet_interval(node, &intv);
    if (intv.first_pid != 223 || intv.last_pid != 224) {
        printf("Failed interval test 1.3. Wanted 223:224. Got %lu:%lu\n",
               intv.first_pid, intv.last_pid);
        exit(0);
    }

    intv.first_pid = 0;
    intv.last_pid = 0;
    node = get_packet_interval(node, &intv);
    if (intv.first_pid != 226 || intv.last_pid != 226) {
        printf("Failed interval test 1.4. Wanted 226:226. Got %lu:%lu\n",
               intv.first_pid, intv.last_pid);
        exit(0);
    }

    while(list_size(&p1))
        list_pop_head(&p1);

    list_push_tail(&p1, LIST_PID(100));
    
    intv.first_pid = 0;
    intv.last_pid = 0;
    node = list_head(&p1);
    node = get_packet_interval(node, &intv);
    if (intv.first_pid != 100 || intv.last_pid != 100) {
        printf("Failed interval test 1.1. Wanted 100:100. Got %lu:%lu\n",
                  intv.first_pid, intv.last_pid);
        exit(0);
    }

    while(list_size(&p1))
        list_pop_head(&p1);

    list_push_tail(&p1, LIST_PID(300));
    list_push_tail(&p1, LIST_PID(301));
    node = list_head(&p1);
    
    intv.first_pid = 0;
    intv.last_pid = 0;
    node = get_packet_interval(node, &intv);
    if (intv.first_pid != 300 || intv.last_pid != 301) {
        printf("Failed interval test 1.1. Wanted 300-103. Got %lu %lu\n",
                  intv.first_pid, intv.last_pid);
        exit(0);
    }
}

void test_packet_intervals()
{
    list_t p1;
    list_t intv_list;
    list_node_t* node;
    packet_interval_t *intv = 0;
    uint32_t res = 0;
    
    list_init(&p1);
    list_init(&intv_list);
    list_push_tail(&p1, LIST_PID(1));
    list_push_tail(&p1, LIST_PID(2));
    list_push_tail(&p1, LIST_PID(3));
    list_push_tail(&p1, LIST_PID(4));
    list_push_tail(&p1, LIST_PID(5));

    list_push_tail(&p1, LIST_PID(7));

    list_push_tail(&p1, LIST_PID(223));
    list_push_tail(&p1, LIST_PID(224));

    list_push_tail(&p1, LIST_PID(226));

    // Grab all intervals and check context
    res = get_packet_intervals(&p1, list_size(&p1), &intv_list);

    if (res != 9) {
        printf("Failed intervals test 1.1. Wanted 8. Got %u\n", res);
        exit(0);
    }

    node = list_head(&intv_list);
    intv = node->data.data;
    if (intv->first_pid != 1 || intv->last_pid != 5) {
        printf("Failed intervals test 1.2. Wanted 1:5. Got %lu:%lu\n",
               intv->first_pid, intv->last_pid);
        exit(0);
    }

    node = list_next(node);
    intv = node->data.data;
    if (intv->first_pid != 7 || intv->last_pid != 7) {
        printf("Failed intervals test 1.3. Wanted 7:7. Got %lu:%lu\n",
               intv->first_pid, intv->last_pid);
        exit(0);
    }

    node = list_next(node);
    intv = node->data.data;
    if (intv->first_pid != 223 || intv->last_pid != 224) {
        printf("Failed intervals test 1.4. Wanted 223:224. Got %lu:%lu\n",
               intv->first_pid, intv->last_pid);
        exit(0);
    }

    node = list_next(node);
    intv = node->data.data;
    if (intv->first_pid != 226 || intv->last_pid != 226) {
        printf("Failed intervals test 1.4. Wanted 226:226. Got %lu:%lu\n",
               intv->first_pid, intv->last_pid);
        exit(0);
    }
}
    
#endif // INCLUDE_TEST
