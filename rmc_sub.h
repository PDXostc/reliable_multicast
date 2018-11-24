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

    // Set to 1 if this packet does not need to be acked.
    // Used when we receive packet via tcp.
    uint8_t skip_acknowledgement;

    // Provided by sub_packet_received()
    // Retrieved by sub_packet_user_data()
    user_data_t pkg_user_data;   

    // Node referering to self in received_ts sub_publisher::list
    // Allows for O(1) removal of self once we have been processed
    struct _sub_packet_node* received_ts_entry;
} sub_packet_t;


RMC_LIST(sub_packet_list, sub_packet_node, sub_packet_t*) 
typedef sub_packet_list sub_packet_list_t;
typedef sub_packet_node sub_packet_node_t;


// Used by sub_get_ack_sub_pid_intervals
typedef struct sub_pid_interval {
    packet_id_t first_pid; // First packet ID in interval
    packet_id_t last_pid; // LAst packet ID in interval
} sub_pid_interval_t;


RMC_LIST(sub_pid_interval_list, sub_pid_interval_node, sub_pid_interval_t) 
typedef sub_pid_interval_list sub_pid_interval_list_t;
typedef sub_pid_interval_node sub_pid_interval_node_t;

// A publisher is a feed from a single packet publisher that
// is being processed. It contains the state necessary to drive
// packets toward the cycle described in sub_packet_t aboce.
//  
typedef struct sub_publisher {
    packet_id_t max_pid_ready;         // Highest pid that is ready to be dispatched.
    packet_id_t max_pid_received;      // Maximum PID received.

    // Packets received but need additional packets.
    // Sorted on ascending pid
    sub_packet_list_t received_pid;    

    // Packets received but need additional packets.
    // Sorted on ascending recived_ts
    sub_packet_list_t received_ts;    

    // Received packet intervals.
    // Filled by sub_packet_received().
    // Depletd by sub_interval_acknowledged()
    //
    sub_pid_interval_list received_interval;
} sub_publisher_t; 


extern void sub_init_publisher(sub_publisher_t* pub);

extern int sub_packet_is_duplicate(sub_publisher_t* pub,
                                   packet_id_t pid);

extern int sub_packet_received(sub_publisher_t* pub,
                               packet_id_t pid,
                               void* payload,
                               payload_len_t payload_len,
                               uint8_t skip_acknowledgement, 
                               usec_timestamp_t current_ts,
                               user_data_t pkg_user_data);

// Go through all received packets and move those that are ready to
// be dispathed to the ready queue
// Should be called after one or more calls to sub_receive_packet()
extern void sub_process_received_packets(sub_publisher_t* pub, sub_packet_list_t* dispatch_ready);

extern void sub_reset_publisher(sub_publisher_t*,
                                void (*)(void*, payload_len_t, user_data_t));;


extern  user_data_t sub_packet_user_data(sub_packet_t* pack);
extern int _sub_packet_add_to_received_interval(sub_publisher_t* pub, packet_id_t pid);



#endif // __REL_MCAST_SUB__
