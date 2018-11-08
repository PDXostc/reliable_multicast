// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)


#ifndef __REL_MCAST_SUB_H__
#define __REL_MCAST_SUB_H__
#include "rmc_common.h"
#include "rmc_list.h"
#include "interval.h"

//
// A packet that is either waiting to be sent,
// or has been sent and is collecting acks from all subscribers.
//
typedef struct sub_packet {
    struct _sub_packet_node* owner_node;   // Parent node in 'received' or 'ready' of sub_publisher_t
    struct sub_publisher* publisher;   // Publisher that sent this packet.
    packet_id_t pid;
    void *payload;              // Payload provided by pub_queue_packet()
    payload_len_t payload_len;  // Payload length provided by pub_queue_packet()
    user_data_t pkg_user_data;      // Provided by sub_packet_received()
} sub_packet_t;


RMC_LIST(sub_packet_list, sub_packet_node, sub_packet_t*) 
typedef sub_packet_list sub_packet_list_t;
typedef sub_packet_node sub_packet_node_t;

typedef struct sub_publisher {
    struct sub_context* owner;      // Owning context.
    packet_id_t max_pid_ready;      // Highest pid that is ready to be dispatched.
    packet_id_t max_pid_received;   // Maximum PID received.
    sub_packet_list_t received;     // Packets received but need additional packets. 
    sub_packet_list_t ready;        // Packets ready to be dispatched.
} sub_publisher_t; 


RMC_LIST(sub_publisher_list, sub_publisher_node, sub_publisher_t*) 
typedef sub_publisher_list sub_publisher_list_t;
typedef sub_publisher_node sub_publisher_node_t;

typedef struct sub_context {
    sub_publisher_list_t publishers; // of sub_publisher_t for all publishers we are subscribing to.

    // All arguments are from the sub_packet_received() call
    void (*sub_payload_free)(void*, payload_len_t, user_data_t pkg_user_data);
} sub_context_t; 

extern void sub_init_context(sub_context_t* ctx,
                             void (*sub_payload_free)(void*, payload_len_t, user_data_t pkg_user_data));

extern int sub_packet_is_duplicate(sub_publisher_t* pub,
                                   packet_id_t pid);

extern int sub_packet_received(sub_publisher_t* pub,
                               packet_id_t pid,
                               void* payload,
                               payload_len_t payload_len,
                               user_data_t pkg_user_data);

// Go through all received packets and move those that are ready to
// be dispathed to the ready queue
// Should be called after one or more calls to sub_receive_packet()
extern void sub_process_received_packets(sub_publisher_t* pub);

extern sub_packet_t* sub_next_ready_packet(sub_publisher_t* ctx);
extern void sub_packet_dispatched(sub_packet_t* pack);
extern void sub_get_missing_packets(sub_publisher_t* sub, intv_list_t* res);
extern void sub_init_publisher(sub_publisher_t* pub, sub_context_t* ctx);
extern sub_publisher_t* sub_find_publisher(sub_context_t* ctx, void* address, int address_len);
extern void sub_remove_publisher(sub_publisher_t* pub);
extern sub_packet_t* sub_get_next_ready_packet(sub_context_t* ctx);
extern int sub_get_ready_packet_count(sub_context_t* ctx);

extern  user_data_t sub_packet_user_data(sub_packet_t* pack);

#endif // __REL_MCAST_SUB__
