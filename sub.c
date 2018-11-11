// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "rmc_sub.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>

#include "rmc_list_template.h"

RMC_LIST_IMPL(sub_packet_list, sub_packet_node, sub_packet_t*) 
RMC_LIST_IMPL(sub_publisher_list, sub_publisher_node, sub_publisher_t*) 

// FIXME: Ditch malloc and use a stack-based alloc/free setup that operates
//       on static-sized heap memory allocated at startup. 
static sub_packet_t* _alloc_pending_packet()
{
    sub_packet_t* res = (sub_packet_t*) malloc(sizeof(sub_packet_t));

    assert(res);
    return res;
}

static void _free_pending_packet(sub_packet_t* ppack)
{
    assert(ppack);
    free((void*) ppack);
}

int sub_packet_is_duplicate(sub_publisher_t* pub, packet_id_t pid)
{
    sub_packet_t cmp_pack = { .pid = pid };
    // Is packet duplicate?
    // FIXME: Setup hash table for pub->received so that we
    // can find dups faster
    //
    return ((pub->max_pid_ready != 0 && pid < pub->max_pid_ready) ||
            sub_packet_list_find_node(&pub->received,
                                  &cmp_pack,
                                  lambda(int, (sub_packet_t* dt1,
                                               sub_packet_t* dt2) {
                                             return dt1->pid == dt2->pid;
                                         })))?1:0;
}


int sub_packet_received(sub_publisher_t* pub, packet_id_t pid,
                        void* payload,
                        payload_len_t payload_len,
                        usec_timestamp_t current_ts,
                        user_data_t pkg_user_data)
{
    sub_packet_t* pack = 0;
    assert(pub);

    pack = _alloc_pending_packet();
    pack->pid = pid;
    pack->payload = payload;
    pack->payload_len = payload_len;
    pack->publisher = pub;
    pack->pkg_user_data = pkg_user_data;
    pack->received_ts = current_ts;

    if (pub->max_pid_received < pid)
        pub->max_pid_received = pid;
    
    //
    // Insert on ascending pid sort order, running from tail toward head
    // since our received packet probably belongs closer to the tail of
    // the received list than the beginning
    // 
    pack->owner_node = 
        sub_packet_list_insert_sorted_rev(&pub->received,
                                          pack,
                                          lambda(int, (sub_packet_t* n_dt, sub_packet_t* o_dt) {
                                                  return (n_dt->pid < o_dt->pid)?-1:
                                                      ((n_dt->pid > o_dt->pid)?1:
                                                       0);
                                              }));
    return 1;
}


// Go through all received packets and move those that are ready to
// be dispathed to the ready queue
// Should be called after one or more calls to sub_receive_packet()
// Do not call too often since it is medium expensive on execution.
void sub_process_received_packets(sub_publisher_t* pub)
{
    sub_packet_node_t* node = 0;
    assert(pub);
    
    // Move over all packets that are sequential to the
    // last successfully received packet from the received
    // queue top
    node = sub_packet_list_head(&pub->received);

    // Initialize pub->max_pid_ready if not setup already
    if (node && !pub->max_pid_ready)
        pub->max_pid_ready = node->data->pid - 1;

    while(node) {
        if (pub->max_pid_ready &&
            node->data->pid != pub->max_pid_ready + 1)
            break;
        // This nodeet can be moved over to the ready queue
        // This queue is sorted ascending pid porder
        sub_packet_list_unlink(node);
        sub_packet_list_insert_sorted_node_rev(&pub->dispatch_ready,
                                                 node,
                                                 lambda(int, (sub_packet_t* n_dt, sub_packet_t* o_dt) {
                                                         return (n_dt->pid > o_dt->pid)?1:
                                                             ((n_dt->pid < o_dt->pid)?-1:
                                                              0);
                                                     }
                                                     ));
        node = sub_packet_list_head(&pub->received);
        pub->max_pid_ready++;
    }

    // If we moved all received packets over to the ready list,
    // then no new holes are found.
    if (!node) 
        return;

    
}
    

sub_packet_t* _sub_next_dispatch_ready(sub_publisher_t* pub)
{
    sub_packet_node_t* node = 0;
    
    assert(pub);
    node = sub_packet_list_head(&pub->dispatch_ready);
    return node?node->data:0;
}



sub_packet_t* _sub_next_ack_ready(sub_publisher_t* pub)
{
    sub_packet_node_t* node = 0;
    
    assert(pub);
    node = sub_packet_list_head(&pub->ack_ready);
    return node?node->data:0;
}


// Should be called after sub_process_received_packets() and before
// the next sub_packet_received() call to ensure
// that we operate on a received list that does not
// contain any packets that we can dispatch.
void sub_get_missing_packets(sub_publisher_t* pub, intv_list_t* res)
{
    packet_id_t hole_start = 0;
    packet_id_t hole_end = 0;
    packet_id_t prev_pid = 0;
    sub_packet_node_t* node = 0;

    // Interval list needs to be empty.
    assert(!intv_list_size(res));
    
    // Go through the received packet list and look for holes.
    node = sub_packet_list_head(&pub->received);
    

    if (!node)
        return;

    // Check if we have a hole between the highest
    // pid in the ready queue and the lowest
    // pid in the received queue.
    //
    // Example:
    //
    // pub->dispatch_ready
    // pid 1
    // pid 2 <- pub->max_pid_ready
    // 
    // pub->received
    // pid 5 <- node->data->pid
    // pid 6
    // pid 7
    //
    // There is a hole, pid 3-4, between the max
    // pid that is ready for dispatch and the lowest
    // pid in the received queue.
    //
    if (pub->max_pid_ready &&
        node->data->pid != pub->max_pid_ready - 1) {
        packet_interval_t intv = { .first_pid = pub->max_pid_ready + 1,
                                   .last_pid = node->data->pid - 1 };
        intv_list_push_head(res, intv); 
    }

    // Walk through ascending pids and check for holes
    while(node) {
        sub_packet_t* pack = node->data;

        // Do we have a hole?
        if (prev_pid != 0 && prev_pid != pack->pid - 1) {
            hole_start = prev_pid + 1;
            hole_end = pack->pid - 1;

            // Do we need to create a new interval?
            if (!intv_list_size(res) ||
                intv_list_tail(res)->data.last_pid != hole_start - 1) {

                packet_interval_t intv = { .first_pid = hole_start,
                                           .last_pid = hole_end };

                intv_list_insert_sorted_rev(res,
                                            intv,
                                            lambda(int, (packet_interval_t n_dt, packet_interval_t o_dt) {
                                                    return (n_dt.last_pid < o_dt.last_pid)?-1:
                                                        ((n_dt.last_pid > o_dt.last_pid)?1:
                                                         0);
                                                }
                                                ));
            }
            else 
                // We can extend the last found interval.
                intv_list_tail(res)->data.last_pid = hole_end;
        }

        prev_pid = pack->pid;
        node = sub_packet_list_next(node);
    }
}




void sub_init_publisher(sub_publisher_t* pub, sub_context_t* ctx)
{
    pub->owner = ctx;
    pub->max_pid_received = 0;
    pub->max_pid_ready = 0;
    sub_packet_list_init(&pub->received, 0, 0, 0);
    sub_packet_list_init(&pub->dispatch_ready, 0, 0, 0);
    sub_packet_list_init(&pub->ack_ready, 0, 0, 0);
    sub_publisher_list_push_head(&ctx->publishers, pub);

    return;
}


void sub_remove_publisher(sub_publisher_t* pub,
                          void (*free_cb)(void*, payload_len_t, user_data_t))
{
    sub_context_t* ctx = 0;
    sub_publisher_node_t* pub_node = 0;
    sub_packet_t* pack = 0;

    if (!pub)
        return;

    ctx = pub->owner;
    
    // Find the publisher list node in ctx->publisher so that we
    // can delete it.
    pub_node =  sub_publisher_list_find_node(&ctx->publishers,
                                             pub,
                                             lambda(int, (sub_publisher_t* dt1,
                                                          sub_publisher_t* dt2) {
                                                        return dt1 == dt2;
                                                    }));
    assert(pub_node);
    sub_publisher_list_delete(pub_node);

    // Go through each list and wipe them.
    while(sub_packet_list_pop_head(&pub->received, &pack)) {
        if (free_cb)
            (*free_cb)(pack->payload, pack->payload_len, pack->pkg_user_data);
        _free_pending_packet(pack);
    }

    while(sub_packet_list_pop_head(&pub->dispatch_ready, &pack)) {
        if (free_cb)
            (*free_cb)(pack->payload, pack->payload_len, pack->pkg_user_data);

        _free_pending_packet(pack);
    }

    while(sub_packet_list_pop_head(&pub->ack_ready, &pack)) {
        if (free_cb)
            (*free_cb)(pack->payload, pack->payload_len, pack->pkg_user_data);

        _free_pending_packet(pack);
    }

    return;
}



void sub_init_context(sub_context_t* ctx)
{
    sub_publisher_list_init(&ctx->publishers, 0, 0, 0);
}


int sub_get_dispatch_ready_count(sub_context_t* ctx)
{
    int res = 0;

    // Iterate across all publishers and sum up all packets ready to
    // be dispatched.
    sub_publisher_list_for_each(&ctx->publishers,
                                lambda(uint8_t, (sub_publisher_node_t* pub_node, void* res) {
                                        *((int*) res) += sub_packet_list_size(&pub_node->data->dispatch_ready);
                                        return 1;
                                    }),
                                (void*) &res);
    return res;
}


sub_packet_t* sub_get_next_dispatch_ready(sub_context_t* ctx)
{
    sub_publisher_node_t* node = sub_publisher_list_head(&ctx->publishers);

    // Iterate across all publishers to find one with packets ready to
    // be dispatched.
    while(node) {
        sub_packet_t* res = _sub_next_dispatch_ready(node->data);
        if (res) 
            return res;

        node = sub_publisher_list_next(node);
    }

    return 0;
}

int sub_get_ack_ready_count(sub_context_t* ctx)
{
    int res = 0;

    // Iterate across all publishers and sum up all packets ready to
    // be acknowledged.
    sub_publisher_list_for_each(&ctx->publishers,
                                lambda(uint8_t, (sub_publisher_node_t* pub_node, void* res) {
                                        *((int*) res) += sub_packet_list_size(&pub_node->data->ack_ready);
                                        return 1;
                                    }),
                                (void*) &res);
    return res;
}


// Move from dispatch_ready to ack_ready
void sub_packet_dispatched(sub_packet_t* pack)
{
    sub_packet_node_t* node = 0;

    assert(pack);
    assert(pack->owner_node);
    assert(pack->publisher);

    // Unlink from ready list. 
    node = pack->owner_node;
    sub_packet_list_unlink(node);
    sub_packet_list_insert_sorted_node_rev(&pack->publisher->ack_ready,
                                           node,
                                           lambda(int, (sub_packet_t* n_dt, sub_packet_t* o_dt) {
                                                   return (n_dt->pid > o_dt->pid)?1:
                                                       ((n_dt->pid < o_dt->pid)?-1:
                                                        0);
                                               }
                                               ));
}


// Packet ack has been sent. Delete.
// pack->payload has to be freed by caller.
void sub_packet_acknowledged(sub_packet_t* pack)
{
    sub_packet_node_t* node = 0;

    assert(pack);
    assert(pack->owner_node);
    assert(pack->publisher);

    // Unlink from ready list. 
    sub_packet_list_delete(pack->owner_node);
}



inline user_data_t sub_packet_user_data(sub_packet_t* pack)
{
    return pack?(pack->pkg_user_data):(user_data_t) { .u64 = 0};
}


// Grab all packets that were received before timeout_ts
// from the given publisher
static void _sub_get_timed_out_pub_packets(sub_publisher_t* pub,
                                           usec_timestamp_t timeout_ts,
                                           sub_packet_list_t* result)
{
    // Traverse all ack_ready packets for publisher and add those
    // older than timeout_ts to result.
    sub_packet_list_for_each_rev(&pub->ack_ready,
                                 // For each packet, check if their oldest inflight packet has a sent_ts
                                 // timestamp older than max_age. If so, add it to result.
                                 lambda(uint8_t, (sub_packet_node_t* pnode, void* udata) {
                                         if (pnode->data->received_ts <= timeout_ts)
                                             sub_packet_list_push_tail(result, pnode->data);
                                         return 1;
                                     }), 0);

}


// Grab all packets that were received before timeout_ts
// from all publishers
void sub_get_timed_out_packets(sub_context_t* ctx,
                               usec_timestamp_t timeout_ts,
                               sub_packet_list_t* result)
{
    assert(ctx);
    assert(result);
    
    // Traverse all publishers and harvest their timed out ack_ready packets
    sub_publisher_list_for_each(&ctx->publishers,
                                lambda(uint8_t, (sub_publisher_node_t* pnode, void* udata) {
                                        _sub_get_timed_out_pub_packets(pnode->data, timeout_ts, result);
                                        return 1;
                                    }), 0);
}



