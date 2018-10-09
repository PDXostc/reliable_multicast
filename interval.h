// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)


#ifndef __INTERVAL_H__
#define __INTERVAL_H__
#include <stdint.h>

typedef uint64_t packet_id_t;

typedef struct packet_interval {
    packet_id_t first_pid; // First packet ID in interval
    packet_id_t last_pid; // LAst packet ID in interval
} packet_interval_t;

#include "rmc_list.h"

RMC_LIST(intv_list, intv_node, packet_interval_t) 
typedef intv_list intv_list_t;
typedef intv_node intv_node_t;

RMC_LIST(pid_list, pid_node, packet_id_t) 
typedef pid_list pid_list_t;
typedef pid_node pid_node_t;


extern pid_node_t* get_packet_interval(pid_node_t* start,
                                       packet_interval_t* interval);

extern uint32_t get_packet_intervals(pid_list_t* packets,
                                     uint32_t max_packet_count,
                                     intv_list_t* result_intervals);
#endif
