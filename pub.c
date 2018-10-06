// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "rmc_pub.h"
#include <assert.h>

// A packet that can 
typedef struct pending_packet {
    packet_id_t pid;
    // If ref_count == 0, then the packet has not yet been sent.
    // If ref_count > 0, then the packet has been sent and can be found
    // in 'ref_count' subscriber::inflight_packets lists
    uint32_t ref_count; 
    list_node_t* pending_node; // Back pointer to pub_context::pending
    payload_len_t payload_len;
    void *payload;
} pending_packet_t;


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
// have received an ack, and the packet can be removed.
//
typedef struct subscriber {
    pub_context_t* context;
    list_t inflight_packets; // Contains pointers to
                             // pending_packet_t sent but not
                             // acknowledged.
} subscriber_t; 


// TODO: Ditch malloc and use a stack-based alloc/free setup that operates
//       on static-sized heap memory allocated at startup. 
static pending_packet_t* _alloc_pending_packet()
{
    pending_packet_t* res = (pending_packet_t*) malloc(sizeof(pending_packet_t));

    assert(res);
    return res;
}

static void _free_pending_packet(pending_packet_t* hpack)
{
    assert(hpack);
    free((void*) hack);
}


// TODO: Ditch malloc and use a stack-based alloc/free setup that operates
//       on static-sized heap memory allocated at startup. 
static subscriber_t* _alloc_subscriber()
{
    subscriber_t* res = (subscriber_t*) malloc(sizeof(subscriber_t));

    assert(res);
    return res;
}

static void _free_subscriber(subscriber_t* sub)
{
    assert(sub);
    free((void*) hack);
}

static packet_id_t _next_pid(pub_context_t* ctx)
{
    assert(ctx);

    return ctx->next_pid++;
}

       
void pub_init_context(pub_context_t* ctx,
                      uint32_t pending_max_length,
                      void (*payload_free)(void*, payload_len_t))
{
    assert(ctx);

    ctx->pending_max_length = pending_max_length;
    list_init(&ctx->subscribers);
    list_init(&ctx->pending);
    ctx->payload_free = payload_free;
    ctx->next_pid = 1;

}


void pub_init_subscriber(subscriber_t* sub, pub_context_t* ctx)
{
    assert(sub);
    assert(ctx);

    sub->context = ctx;
    list_init(&ctx->unackwnowledged_packets);
    list_init(&ctx->outbound_queue);
}


packet_id_t pub_queue_packet(pub_context* ctx, void* payload, payload_len_t payload_len)
{
    list_node_t *node = 0;
    pending_packet_t* hpack = 0;
    packet_id_t pid;
    assert(ctx);
    assert(data);

    hpack = _alloc_pending_packet();

    hpack->pid = _next_pid(ctx);
    hpack->payload = payload;
    hpack->payload_len = payload_len;
    hpack->ref_count = 0;


    // Insert into ctx->pending, sorted in ascending order.
    // Store the node in hpack as a back pointer for easier future
    // deletion.
    hpack->pending_node = 
        list_insert_sorted(ctx->pending,
                           LIST_DATA(hpack),
                           lambda(int, (node_data_t* new_hpack, node_data_t* old_hpack) {
                                   (new_hpack->pid < old_hpack)?1:
                                       ((new_hpack->pid > old_hpack)?-1:
                                        0)
                                       }
                               ));

    
}


void pub_packet_sent(pub_context* ctx, pending_packet_t* hpack)
{
    list_node_t* sub_node = 0; // Subscribers in ctx,

    assert(ctx);

    // Traverse all subscribers and insert hpack as 
    sub_node = list_head(ctx->sub
    while(sub_node) {
        subscriber_t* sub = (subscriber_t*) sub_node->data.data;
        // Insert the new pending_packet_t in the descending
        // packet_id sorted list of the subscriber's inflight packets.
        list_insert_sorted(sub->inflight_packets,
                           hpack,
                           lambda(int, (node_data_t* new_hpack, node_data_t* old_hpack) {
                                   (new_hpack->pid > old_hpack)?1:
                                       ((new_hpack->pid < old_hpack)?-1:
                                        0)
                                       }
                               ));
        hpack->ref_count++;
        node = list_next(node);
    }
}

void pub_packet_ack(subscriber_t* sub, packet_id_t pid)
{
    list_node_t* node = 0; // Packets
    pending_packet_t* hpack = 0;

    assert(ctx);

    // Traverse all inflight packets of the subscriber and find the
    // one matching pid. We do this from the rear since we are more likely
    // to get an ack on an older packet with a lower pid than a newer one
    node = list_tail(sub->inflight_packets);

    while(node) {
        hpack = node->data.data;

        if (hpack->pid == pid)
            break;

        node = list_prev(node);
    }

    // No inflight packet found for the ack.
    // This should never happen since we get the acks
    // via TCP that cannot ack the same packet twice.
    if (!node) {
        printf("pub_packet_ack(%lu): No matching packet found in subscriber inflight packets.\n", pid);
        exit(255); // TOOD: Handle at calling level.
    }

    // Delete from subscriber's inflight packets
    list_delete(node);

    // Decrease ref counter
    hpack->ref_count--;

    // If ref_count is zero, then all subscribers have acked the
    // packet, which can now be removed from the pending.
    if (!hpack->ref_count)
        list_delete(hpack->list_delete);

    // Free data using function provided to pub_init_context
    (*sub->ctx->payload_free)(hpack->payload, hpack->payload_len);

    // Delete the hpack.
    _free_pending_packet(hpack);
}


