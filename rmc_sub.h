// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)


#ifndef __REL_MCAST_SUB_H__
#define __REL_MCAST_SUB_H__
#include "rel_mcast_common.h"

typedef struct sub_context {
    list_t publishers; // of sub_publisher_t for all publishers we are subscribing to.
    void (*payload_free)(void*, payload_len_t);

} sub_context_t; 

typedef struct sub_publisher {
    packet_id_t max_pid_received;   // Maximum PID received
    packet_id_t max_pid_processed;  // Maximum PID processed
    list_t received;                // Packets received but need additional packets. Desc
    list_t ready;                   // Packets ready to be dispatched.
    list_t holes;                   // Missing packets with lower PIs than max_pid
} sub_publisher_t; 

//
// A packet that is either waiting to be sent,
// or has been sent and is collecting acks from all subscribers.
//
typedef struct sub_pending_packet {
    list_node_t* parent_node;   // Parent node in 'received' or 'ready' of sub_publisher_t
    packet_id_t pid;
    void *payload;              // Payload provided by pub_queue_packet()
    payload_len_t payload_len;  // Payload length provided by pub_queue_packet()
} sub_pending_packet_t;


extern void sub_init_context(sub_context_t* ctx,
                             void (*payload_free)(void*, payload_len_t));

extern void sub_receive_packet(sub_context_t* ctx,
                               packet_id_t pid,
                               void* payload,
                               payload_len_t payload_len);

// Go through all received packets and move those that are ready to
// be dispathed to the ready queue
// Should be called after one or more calls to sub_receive_packet()
void sub_process_received_paclets(sub_publisher_t* pub)

extern sub_pending_packet_t* sub_next_ready_packet(sub_context_t* ctx);
extern void sub_confirm_packet(sub_context_t* ctx, sub_pending_packet_t* pack);
extern uint32_t sub_get_missing_packets(sub_context_t* ctx, interval_t* res);

#endif // __REL_MCAST_SUB__
