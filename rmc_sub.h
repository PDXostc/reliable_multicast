// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

// rmc_sub.h - Handle packets subscribed to.
//  This file contains data structures and functions to handle incoming packets
//  sent by one or more publishers.
//  The functions in here are network agnostic and only deals with
//  driving packet meta-data and payload through their maturation
//  process described below.
//
#ifndef __REL_MCAST_SUB_H__
#define __REL_MCAST_SUB_H__
#include "rmc_common.h"
#include "rmc_list.h"
#include "interval.h"


//
// Packet has been received via multicast or tcp.
// Packet can be in one of the following queues.
//
// publisher->received
//   Packet has been received but cannot be processed due to missing packets
//   with lower pids, forming holes in the receive stream.
//
// publisher->dispatch_ready.
//    Packet is ready to be procesed by the caller through sub_get_next_dispatch_ready()
//    calls. 
//
// publisher->ack_ready
//    The packet has been dispatched and is ready to be acknowledged back to the
//    the publisner.
//
//
// Call sequence to propagate packet is:
//
// sub_packet_received()
//   Packet has been received from network and is pending processing.
//
// sub_process_received_packets()
//   Move all consequtive packets, ready to be dispatched, from received to dispatch_ready queue.
//
// sub_packet_dispatched()
//   Packet has been processed by caller. Move from dispatch_ready to ack_ready queue.
//
// sub_packet_acknowledged()
//   Packet has been acknowledged to publisher and can be freed.
//   **Please note that the caller still has to free packet->payload**
//
typedef struct sub_packet {
    struct _sub_packet_node* owner_node;   // Parent node in 'received' or 'ready' of sub_publisher_t
    struct sub_publisher* publisher;   // Publisher that sent this packet.

    // Time stamp when packet was placed in received queue. Used
    // to calculate when we need to ack it.
    usec_timestamp_t received_ts; 

    // Packet ID as received from network.
    packet_id_t pid;

    // Payload data allocation is done by caller and provided via
    // rmc_packet_received() call.
    // Caller needs to free payload once sub_packet_acknowledged() has
    // been called.
    void *payload; 
    // Payload length provided by pub_queue_packet()
    payload_len_t payload_len;  

    // Provided by sub_packet_received()
    // Retrieved by sub_packet_user_data()
    user_data_t pkg_user_data;   
} sub_packet_t;


RMC_LIST(sub_packet_list, sub_packet_node, sub_packet_t*) 
typedef sub_packet_list sub_packet_list_t;
typedef sub_packet_node sub_packet_node_t;

// A publisher is a feed from a single packet publisher that
// is being processed. It contains the state necessary to drive
// packets toward the cycle described in sub_packet_t aboce.
//  
typedef struct sub_publisher {
    struct sub_context* owner;         // Owning context.
    packet_id_t max_pid_ready;         // Highest pid that is ready to be dispatched.
    packet_id_t max_pid_received;      // Maximum PID received.
    sub_packet_list_t received;        // Packets received but need additional packets. 
} sub_publisher_t; 


RMC_LIST(sub_publisher_list, sub_publisher_node, sub_publisher_t*) 
typedef sub_publisher_list sub_publisher_list_t;
typedef sub_publisher_node sub_publisher_node_t;

// A single subscriber context that collects the feeds
// of multiple publishers into a single feed.
// We move packdets that have been processed by sub_process_received_packets()
// int dispatch_ready and ack_ready on a context level instead of a per-publisher level
// since they can all be treated as a single pool of actionablke packets at this point.
//
// The packets in disaptch_ready are dropped in at the tail of the list, ensuring
// that all packets from a single publisher are sorted on their publisher-specific ascending
// pid.
//
// The packets in ack_ready are sorted on received_time, allowig for quick retrieval based
// on when it is time to acknowledge them.
//
typedef struct sub_context {
    sub_publisher_list_t publishers; // of sub_publisher_t for all publishers we are subscribing to.
    sub_packet_list_t dispatch_ready;  // Packets ready to be dispatched.
    sub_packet_list_t ack_ready;       // Packets ready to be acknowledged.
} sub_context_t; 

extern void sub_init_context(sub_context_t* ctx);

extern int sub_packet_is_duplicate(sub_publisher_t* pub,
                                   packet_id_t pid);

extern int sub_packet_received(sub_publisher_t* pub,
                               packet_id_t pid,
                               void* payload,
                               payload_len_t payload_len,
                               usec_timestamp_t current_ts,
                               user_data_t pkg_user_data);

// Go through all received packets and move those that are ready to
// be dispathed to the ready queue
// Should be called after one or more calls to sub_receive_packet()
extern void sub_process_received_packets(sub_publisher_t* pub);

extern void sub_get_missing_packets(sub_publisher_t* sub, intv_list_t* res);
extern void sub_init_publisher(sub_publisher_t* pub, sub_context_t* ctx);
extern sub_publisher_t* sub_find_publisher(sub_context_t* ctx, void* address, int address_len);
extern void sub_remove_publisher(sub_publisher_t*,
                                 void (*)(void*, payload_len_t, user_data_t));;

extern sub_packet_t* sub_get_next_dispatch_ready(sub_context_t* ctx);
extern int sub_get_dispatch_ready_count(sub_context_t* ctx);
extern void sub_packet_dispatched(sub_packet_t* pack);

// Caller needs to free pack->payload once this call returns
void sub_get_timed_out_packets(sub_context_t* ctx,
                               usec_timestamp_t timeout_ts,
                               sub_packet_list_t* result);


extern int sub_get_acknowledge_ready_count(sub_context_t* ctx);
extern sub_packet_t* sub_get_next_acknowledge_ready(sub_context_t* ctx);
extern void sub_packet_acknowledged(sub_packet_t* pack);

extern  user_data_t sub_packet_user_data(sub_packet_t* pack);

// Get the timestamp when the oldest packet was received that we have
// yet to send an acknowledgement back to the publisher for.
extern int sub_get_oldest_unacknowledged_packet(sub_context_t* ctx,
                                                usec_timestamp_t* received_ts);

#endif // __REL_MCAST_SUB__
