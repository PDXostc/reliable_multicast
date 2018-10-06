// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)


#ifndef __REL_MCAST_PUB_H__
#define __REL_MCAST_PUB_H__
#include "list.h"
#include "rmc_common.h"


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
    list_t subscribers; // of subscriber_t
    list_t pending; // of pending_packet_t. Used by subscriber_t::inflights
    uint32_t pending_max_length;
    packet_id_t next_pid;
    void (*payload_free)(void*, payload_len_t);
} pub_context_t;


// Init a new context.
//
// pending_max_length specifies the maximum number of inflights packet
// we should keep waiting to be properly acked by all subscribers
// before bombing out.
//
// payload_free will be called to free the data pointed to by 'payload'
// in pub_queue_packet() once the packet has been ack:ed by all subscribers.
//
extern void pub_init_context(pub_context_t* ctx,
                             uint32_t pending_max_length,
                             void (*payload_free)(void*, payload_len_t));

extern void pub_init_subscriber(subscriber_t* sub, pub_context_t* ctx);
extern packet_id_t pub_queue_packet(pub_context* ctx, void* payload, payload_len_t payload_len);
extern void_t pub_packet_sent(pub_context* ctx, packet_id_t pid);

extern void pub_packet_ack(subscriber_t* sub, packet_id_t pid);

#endif // __RMC_PUB_H__
