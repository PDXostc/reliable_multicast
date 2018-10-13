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

#include "rmc_list_template.h"

RMC_LIST_IMPL(sub_packet_list, sub_packet_node, sub_packet_t*) 
RMC_LIST_IMPL(sub_publisher_list, sub_publisher_node, sub_publisher_t*) 

// TODO: Ditch malloc and use a stack-based alloc/free setup that operates
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

static sub_publisher_t* _alloc_publisher()
{
    sub_publisher_t* res = (sub_publisher_t*) malloc(sizeof(sub_publisher_t));

    assert(res);
    return res;
}

static void _free_publisher(sub_publisher_t* pub)
{
    assert(pub);
    free((void*) pub);
}



int sub_packet_received(sub_publisher_t* pub,
                        packet_id_t pid,
                        void* payload,
                        payload_len_t payload_len)
{
    sub_packet_t* pack = 0;
    sub_packet_t cmp_pack = { .pid = pid };
    assert(pub);

    // Is packet duplicate?
    // FIXME: Setup hash table for pub->received so that we
    // can find dups faster
    //
    if ((pub->max_pid_ready != 0 && pid < pub->max_pid_ready) ||
        sub_packet_list_find_node(&pub->received,
                                  &cmp_pack,
                                  lambda(int, (sub_packet_t* dt1,
                                               sub_packet_t* dt2) {
                                             return dt1->pid == dt2->pid;
                                         })))
        return 0;
        
    pack = _alloc_pending_packet();
    pack->pid = pid;
    pack->payload = payload;
    pack->payload_len = payload_len;
    pack->publisher = pub;

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
    while(node) {
        if (pub->max_pid_ready &&
            node->data->pid != pub->max_pid_ready + 1)
            break;
        // This nodeet can be moved over to the ready queue
        // This queue is sorted ascending pid porder
        sub_packet_list_unlink(node);
        sub_packet_list_insert_sorted_node_rev(&pub->ready,
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
    

sub_packet_t* sub_next_ready_packet(sub_publisher_t* pub)
{
    sub_packet_node_t* node = 0;
    
    assert(pub);
    node = sub_packet_list_head(&pub->ready);
    return node?node->data:0;
}



void sub_packet_dispatched(sub_packet_t* pack)
{
    sub_packet_node_t* node = 0;
    sub_context_t* ctx = 0;

    assert(pack);
    assert(pack->owner_node);
    assert(pack->publisher);

    ctx = pack->publisher->owner;

    // Unlink from ready list. Save the node
    sub_packet_list_unlink(pack->owner_node);

    if (ctx->payload_free)
        (*ctx->payload_free)(pack->payload, pack->payload_len);
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
    // pub->ready
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


sub_publisher_t* sub_add_publisher(sub_context_t* ctx)
{
    sub_publisher_t* pub = _alloc_publisher();

    pub->owner = ctx;
    pub->max_pid_received = 0;
    pub->max_pid_ready = 0;
    sub_packet_list_init(&pub->received, 0, 0, 0);
    sub_packet_list_init(&pub->ready, 0, 0, 0);
    sub_publisher_list_push_head(&ctx->publishers, pub);

    return pub;
}

void sub_delete_publisher(sub_publisher_t* pub)
{
    sub_publisher_node_t* pub_node = 0;
    sub_context_t* ctx = 0;

    assert(pub);

    ctx = pub->owner;
    pub_node = sub_publisher_list_find_node(&ctx->publishers,
                                            pub,
                                            lambda(int, (sub_publisher_t* dt1,
                                                         sub_publisher_t* dt2) {
                                                       return dt1 == dt2;
                                                   }));
                   
    // We should have a hit in the publisher's list
    assert(pub_node);
    sub_publisher_list_delete(pub_node);

    // Go through each list and wipe them.
    while(sub_packet_list_size(&pub->received)) {
        sub_packet_t* pack = sub_packet_list_pop_head(&pub->received);
        (*ctx->payload_free)(pack->payload, pack->payload_len);
        _free_pending_packet(pack);
    }


    while(sub_packet_list_size(&pub->ready)) {
        sub_packet_t* pack = sub_packet_list_pop_head(&pub->ready);
        (*ctx->payload_free)(pack->payload, pack->payload_len);
        _free_pending_packet(pack);
    }


    _free_publisher(pub);
    return;
}


void sub_init_context(sub_context_t* ctx,
                      void (*payload_free)(void*, payload_len_t))
{
    sub_publisher_list_init(&ctx->publishers, 0, 0, 0);
    ctx->payload_free = payload_free;
}
