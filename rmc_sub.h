// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)


#ifndef __REL_MCAST_SUB_H__
#define __REL_MCAST_SUB_H__
#include "list.h"
#include "rel_mcast_common.h"

typedef struct subscriber {
    list_t unprocessed_packets; // Sorted on ascending packet_id order.
    list_t outbound_queue;
} subscriber_t; 


extern void process_packet(packet_id_t pid, void* data, payload_len_t length);



#endif // __REL_MCAST_SUB__
