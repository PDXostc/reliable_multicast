// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)


#ifndef __REL_MCAST_PUB_H__
#define __REL_MCAST_PUB_H__

#include "rmc_common.h"
#include "rmc_list.h"

struct pub_subscriber;

//
// A packet that is either waiting to be sent,
// or has been sent and is collecting acks from all subscribers.
//
typedef struct pub_packet {
    packet_id_t pid;
    // ref_count == 0 -> The packet has not yet been sent.
    // ref_count > 0  -> The packet has been sent and can be found
    //                   in 'ref_count' subscriber::inflight_packets
   //                   lists.
    uint32_t ref_count;

    // Back pointer to pub_context::queued or pub_context::pending, depending
    // on if the packet has been queud or sent.
    // Allows for quick movement of packet as it changes status.
    struct _pub_packet_node* parent_node;

    usec_timestamp_t send_ts;   // When was the packet sent
    void *payload;              // Payload provided by pub_queue_packet()
    payload_len_t payload_len;  // Payload length provided by pub_queue_packet()
    user_data_t pkg_user_data;  // Provided by queue_packet
} pub_packet_t;

RMC_LIST(pub_packet_list, pub_packet_node, pub_packet_t*)
typedef pub_packet_list pub_packet_list_t;
typedef pub_packet_node pub_packet_node_t;

// Each subscriber is hosted by a context.
// Each subscriber has a list of pointers to pending_packet_t owned by
// context->pending.
//
// A pending packet is added to inflight_packets when it is multicasted
// out.
//
// A pending packet is deleted from inflight_packets when a tcp-sent
// ack is received from the subscriber.
//
// When the pending_packet_t::ref_count reaches 0, all subscribers
// have received an ack, and the packet can be ermoved.
//
typedef struct pub_subscriber {
    struct pub_context* context;
    // Contains pointers to pending_packet_t sent but not
    // acknowledged.
    pub_packet_list_t inflight;
    user_data_t user_data;
} pub_subscriber_t;

RMC_LIST(pub_sub_list, pub_sub_node, pub_subscriber_t*)
typedef pub_sub_list pub_sub_list_t;
typedef pub_sub_node pub_sub_node_t;


// A publisher context.  Each publisher can have one or more
// subscribers, each hosted as a subscriber_t struct pointed to by the
// 'subscribers' list.
//
// When a packet is queued for multicast by pub_queue_packet() it's
// payload and packed id is stored in pending as pending_packet_t
// structs.  When the packet is sent out via multicast, it is reported
// by a call to pub_packet_sent(), which will add a pointer to the
// given pending_packet_t to 'subscriber_t::inflight_packets' of all
// subscribers in 'subscriber'
//
// When a packet is acked by a subscriber via a pub_packet_ack() call,
// the corresponding pending_packet_t struct will be removed from the
// subscriber's 'inflight_packets' list, and the pending packets
// reference counter is decreased by 1.
//
// When the reference counter reaches zero, all subscribers have acked
// the packet and the pending_packet_t is removed from the 'pending'
// list and is freed.
//
typedef struct pub_context {
    pub_sub_list_t subscribers; // of pub_subscriber_t
    pub_packet_list_t queued;   // of pub_packet_t of packets waiting to be sent.

    // List of pub_packet_t sent and awaiting acks. Packets in this list
    // are referredd to by subscriber_t::inflight.
    pub_packet_list_t inflight; 
    packet_id_t next_pid;
} pub_context_t;


// Init a new context.
//
// payload_free will be called to free the data pointed to by 'payload'
// in pub_queue_packet() once the packet has been ack:ed by all subscribers.
//
extern void pub_init_context(pub_context_t* ctx);

extern void pub_init_subscriber(pub_subscriber_t* sub,
                                pub_context_t* ctx,
                                user_data_t sub_user_data);

// Clean up sub and free all data related to its inflight packets.
void pub_reset_subscriber(pub_subscriber_t* sub,
                          void (*pub_payload_free)(void* payload,
                                                   payload_len_t payload_len,
                                                   user_data_t user_data));

// Payload will be freed by callback to (*pub_payload_free)() argument
// of pub_packet_ack()
extern packet_id_t pub_queue_packet(pub_context_t* ctx,
                                    void* payload,
                                    payload_len_t payload_len,
                                    user_data_t pkg_user_data);


extern pub_packet_t* pub_next_queued_packet(pub_context_t* ctx);
extern user_data_t pub_packet_user_data(pub_packet_t* ppack);
extern void pub_packet_sent(pub_context_t* ctx,
                            pub_packet_t* ppack,
                            usec_timestamp_t send_ts);

extern void pub_packet_ack(pub_subscriber_t* sub,
                           packet_id_t pid,
                           // Called if this was the last subscriber acking the packet
                           // meaning that we can discard it.
                           void (*pub_payload_free)(void* payload,
                                                    payload_len_t payload_len,
                                                    user_data_t user_data));

// Collect all subscribers that have unacknowledged
// packets older than or equal to max_age usecs.
extern void pub_get_timed_out_subscribers(pub_context_t* ctx,
                                          usec_timestamp_t current_ts,     // as reported by rmc_usec_monotonic_timestamp().
                                          usec_timestamp_t timeout_period, // Number of usecs until timeout
                                          pub_sub_list_t* result);

void pub_get_timed_out_packets(pub_subscriber_t* sub,
                               usec_timestamp_t current_ts,     // as reported by rmc_usec_monotonic_timestamp().
                               usec_timestamp_t timeout_period, // Number of usecs until timeout
                               pub_packet_list_t* result);

// Get the time when the oldest packet was sent that we still are waiting
// for an acknowledgement on from the subscriber.
extern int pub_get_oldest_unackowledged_packet(pub_context_t* ctx,
                                               usec_timestamp_t* sent_ts);



extern user_data_t pub_user_data(pub_context_t* ctx);
extern user_data_t pub_subscriber_user_data(pub_subscriber_t* sub);

#endif // __RMC_PUB_H__
