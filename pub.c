// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "rmc_pub.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include "rmc_list_template.h"

RMC_LIST_IMPL(pub_packet_list, pub_packet_node, pub_packet_t*)
RMC_LIST_IMPL(pub_sub_list, pub_sub_node, pub_subscriber_t*)

// FIXME: Ditch malloc and use a stack-based alloc/free setup that operates
//       on static-sized heap memory allocated at startup.
static pub_packet_t* _alloc_pending_packet()
{
    pub_packet_t* res = (pub_packet_t*) malloc(sizeof(pub_packet_t));

    assert(res);
    return res;
}


static void _free_pending_packet(pub_packet_t* ppack)
{
    assert(ppack);
    free((void*) ppack);
}


static packet_id_t _next_pid(pub_context_t* ctx)
{
    assert(ctx);

    return ctx->next_pid++;
}


void pub_init_context(pub_context_t* ctx)
{
    assert(ctx);

    pub_sub_list_init(&ctx->subscribers, 0, 0, 0);
    pub_packet_list_init(&ctx->queued, 0, 0, 0);
    pub_packet_list_init(&ctx->inflight, 0, 0, 0);
    ctx->next_pid = 1;

}


void pub_init_subscriber(pub_subscriber_t* sub, pub_context_t* ctx, user_data_t sub_user_data)
{

    assert(sub);
    assert(ctx);

    sub->context = ctx;
    sub->user_data = sub_user_data;
    pub_packet_list_init(&sub->inflight, 0, 0, 0);
    pub_sub_list_push_tail(&ctx->subscribers, sub);
}


packet_id_t pub_queue_packet(pub_context_t* ctx,
                             void* payload,
                             payload_len_t payload_len,
                             user_data_t pkg_user_data)
{
    pub_packet_node_t *node = 0;
    pub_packet_t* ppack = 0;
    assert(ctx);
    assert(payload);

    ppack = _alloc_pending_packet();

    ppack->pid = _next_pid(ctx);
    ppack->payload = payload;
    ppack->payload_len = payload_len;
    ppack->ref_count = 0;
    ppack->send_ts = 0; // Will be set by pub_packet_sent()
    ppack->pkg_user_data = pkg_user_data; // Handed to (*payload_free)()

    // Insert into ctx->queued, sorted in descending order.
    // We will pop off this list at the tail to get the next
    // node to send in pub_next_queued_packet().
    //
    // Set parent node to the list_node_t representing
    // the pending packet in ctx->queued for quick unlinking.
    //
    ppack->parent_node =
        pub_packet_list_insert_sorted(&ctx->queued,
                                      ppack,
                                      lambda(int, (pub_packet_t* n_dt, pub_packet_t* o_dt) {
                                              (n_dt->pid > o_dt->pid)?1:
                                                  ((n_dt->pid < o_dt->pid)?-1:
                                                   0);
                                          }
                                          ));

    return ppack->pid;
}

pub_packet_t* pub_next_queued_packet(pub_context_t* ctx)
{
    pub_packet_node_t* node = 0;

    assert(ctx);

    node = pub_packet_list_tail(&ctx->queued);

    return node?node->data:0;
}

void pub_packet_sent(pub_context_t* ctx,
                     pub_packet_t* ppack,
                     usec_timestamp_t send_ts)
{
    pub_sub_node_t* sub_node = 0; // Subscribers in ctx,
    pub_packet_node_t* ppack_node = 0;

    assert(ctx);
    assert(ppack);

    // Record the usec timestamp when it was sent.
    ppack->send_ts = send_ts;

    // Unlink the node from queued packets in our context.
    // ppack->parent will still be allocated and can be reused
    // when we insert the ppack into the inflight packets
    // of context
    pub_packet_list_unlink(ppack->parent_node);

    // Insert existing ppack->parent list_node_t struct into
    // the context's inflight packets.
    // Sorted on ascending pid.
    //
    pub_packet_list_insert_sorted_node(&ctx->inflight,
                                       ppack->parent_node,
                                       lambda(int, (pub_packet_t* n_dt, pub_packet_t* o_dt) {
                                               if (n_dt->pid > o_dt->pid)
                                                   return 1;

                                               if (n_dt->pid < o_dt->pid)
                                                   return -1;

                                               return 0;
                                           }
                                           ));

    // Traverse all subscribers and insert ppack into their
    // inflight list.
    // List is sorted on ascending order.
    //
    sub_node = pub_sub_list_head(&ctx->subscribers);
    while(sub_node) {
        pub_subscriber_t* sub = sub_node->data;

        // Insert the new pub_packet_t in the descending
        // packet_id sorted list of the subscriber's inflight packets.
        pub_packet_list_insert_sorted(&sub->inflight,
                                ppack,
                                lambda(int, (pub_packet_t* n_dt, pub_packet_t* o_dt) {
                                   if (n_dt->pid < o_dt->pid)
                                       return -1;

                                   if (n_dt->pid > o_dt->pid)
                                       return 1;

                                   return 0;
                               }
                               ));
        ppack->ref_count++;
        sub_node = pub_sub_list_next(sub_node);
    }
}


void pub_packet_ack(pub_subscriber_t* sub,
                    packet_id_t pid,
                    void (*pub_payload_free)(void* payload,
                                             payload_len_t payload_len,
                                             user_data_t user_data))
{
    pub_packet_node_t* node = 0; // Packets
    pub_packet_t* ppack = 0;

    assert(sub);

    // Traverse all inflight packets of the subscriber and find the
    // one matching pid. We do this from the rear since we are more
    // likely to get an ack on an older packet with a lower pid than a
    // newer one with a higher pid.
    node = pub_packet_list_tail(&sub->inflight);

    while(node) {
        if (node->data->pid == pid)
            break;

        node = pub_packet_list_prev(node);
    }

    // No inflight packet found for the ack.
    // This should never happen since we get the acks
    // via TCP that cannot ack the same packet twice.
    if (!node) {
        printf("pub_packet_ack(%lu): No matching packet found in subscriber inflight packets.\n", pid);
        exit(255); // TOOD: Handle at calling level.
    }

    // Decrease ref counter
    ppack = node->data;

    // Delete from subscriber's inflight packets
    pub_packet_list_delete(node);

    ppack->ref_count--;

    // If ref_count is zero, then all subscribers have acked the
    // packet, which can now be removed from the pub_context_t::pending
    // list. ppack->parent_node points to the list_node_t struct in the pending
    // list that is to be unlinked and deleted.
    //
    if (!ppack->ref_count) {
        pub_packet_list_delete(ppack->parent_node);

        // Free data using function provided with this call.
        if (pub_payload_free)
            (*pub_payload_free)(ppack->payload,
                                ppack->payload_len,
                                ppack->pkg_user_data);

        // Delete the ppack.
        _free_pending_packet(ppack);
    }
}


void pub_get_timed_out_subscribers(pub_context_t* ctx,
                                   usec_timestamp_t current_ts,
                                   usec_timestamp_t timeout_period, // Number of usecs until timeout
                                   pub_sub_list_t* result)
{
    // Traverse all subscribers.
    pub_sub_list_for_each(&ctx->subscribers,
                          // For each subscriber, check if their oldest inflight packet has a sent_ts
                          // timestamp older than max_age. If so, add the subscriber to result.
                          lambda(uint8_t, (pub_sub_node_t* sub_node, void* udata) {
                                  if (pub_packet_list_size(&sub_node->data->inflight) &&
                                      pub_packet_list_tail(&sub_node->data->inflight)->data->send_ts + timeout_period <= current_ts)
                                      pub_sub_list_push_tail(result, sub_node->data);
                                  return 1;
                              }), 0);

}


void pub_get_timed_out_packets(pub_subscriber_t* sub,
                               usec_timestamp_t current_ts,
                               usec_timestamp_t timeout_period, // Number of usecs until timeout
                               pub_packet_list_t* result)
{
    // Traverse all inflight packets for subscriber until we find one that is not timed out.x
    pub_packet_list_for_each_rev(&sub->inflight,
                                 // For each packet, check if their oldest inflight packet has a sent_ts
                                 // timestamp older than max_age. If so, add it to result.
                                 lambda(uint8_t, (pub_packet_node_t* pnode, void* udata) {
                                         if (pnode->data->send_ts + timeout_period <= current_ts) {
                                             pub_packet_list_push_tail(result, pnode->data);
                                             return 1;
                                         }
                                         return 0;
                                     }), 0);
}


// Get the oldest sent packet that we have yet receive an
// acknowledgement for from subscriber
int pub_get_oldest_unackowledged_packet(pub_context_t* ctx, usec_timestamp_t* timeout_ack)
{
    usec_timestamp_t oldest = -1;

    if (!ctx || !timeout_ack)
        return 0;

    // Traverse all subscribers.
    pub_sub_list_for_each(&ctx->subscribers,
                          // Check if the oldest inflight packet of this subscriber is older
                          // than the oldest inflight packet found so far.
                          lambda(uint8_t, (pub_sub_node_t* sub_node, void* udata) {
                                  pub_packet_list_t* lst = &sub_node->data->inflight;
                                  pub_packet_t* pack = 0;
                                  if (!pub_packet_list_size(lst))
                                      return 1;

                                  pack = pub_packet_list_tail(lst)->data;
                                  if (oldest == -1 || pack->send_ts < oldest) {
                                      oldest = pack->send_ts;
                                  }
                                  return 1;
                              }), 0);

    *timeout_ack = oldest;
    return 1;
}

user_data_t pub_packet_user_data(pub_packet_t* ppack)
{
    return ppack?ppack->pkg_user_data:user_data_nil();
}

user_data_t pub_subscriber_user_data(pub_subscriber_t* sub)
{
    return sub?sub->user_data:user_data_nil();
}
