// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)


#include "interval.h"
#include <assert.h>
#include <stdlib.h>

#include "rmc_list_template.h"

RMC_LIST_IMPL(intv_list, intv_node, packet_interval_t) 
RMC_LIST_IMPL(pid_list, pid_node, packet_id_t) 



// Find a consecutive sequence of packet IDs in the packet id-sorted
// list starting with node 'start'.  Return the first node after the
// consecutive sequence was broken by a hole.  Return 0 reached end of
// list
pid_node_t* get_packet_interval(pid_node_t* start, packet_interval_t* interval)
{
    packet_id_t first_pid = start->data;
    packet_id_t last_pid = start->data;

    while(start) {
        // Are we past the first iteration and did we find a hole?
        if (first_pid != last_pid &&
            start->data != last_pid) 
            break;

        last_pid++;
        start = pid_list_next(start);
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
uint32_t get_packet_intervals(pid_list_t* packets,
                              uint32_t max_packet_count,
                              intv_list_t* result_intervals)
{
    uint32_t res = 0;
    pid_node_t* node = 0;
    assert(packets);
    
    if (packets->elem_count == 0)
        return 0;

    node = pid_list_head(packets);

    while(node) {
        packet_interval_t interval;

        node = get_packet_interval(node, &interval);
        intv_list_push_tail(result_intervals, interval);
        res += interval.last_pid - interval.first_pid + 1;
    }

    return res;
}
