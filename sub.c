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
RMC_LIST_IMPL(sub_pid_interval_list, sub_pid_interval_node, sub_pid_interval_t) 

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
            sub_packet_list_find_node(&pub->received_pid,
                                      &cmp_pack,
                                      lambda(int, (sub_packet_t* dt1,
                                                   sub_packet_t* dt2) {
                                                 return dt1->pid == dt2->pid;
                                             })))?1:0;
}


int sub_packet_received(sub_publisher_t* pub, packet_id_t pid,
                        void* payload,
                        payload_len_t payload_len,
                        uint8_t skip_acknowledgement,
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
    pack->skip_acknowledgement = skip_acknowledgement;
    pack->pkg_user_data = pkg_user_data;
    pack->received_ts = current_ts;

    if (pub->max_pid_received < pid)
        pub->max_pid_received = pid;
    
    // Insert on ascending pid sort order, running from tail toward head
    // since our received packet probably belongs closer to the tail of
    // the received list than the beginning
    sub_packet_list_insert_sorted_rev(&pub->received_pid,
                                      pack,
                                      lambda(int, (sub_packet_t* n_dt, sub_packet_t* o_dt) {
                                              return (n_dt->pid < o_dt->pid)?-1:
                                                  ((n_dt->pid > o_dt->pid)?1:
                                                   0);
                                          }));

    // Insert on ascending received_ts sort order, running from tail toward head
    // since our received packet probably belongs closer to the tail of
    // the received list than the beginning
    // Save list node that was created for quick removal in sub_process_received_packets()
    //
    pack->received_ts_entry =
        sub_packet_list_insert_sorted_rev(&pub->received_ts,
                                          pack,
                                          lambda(int, (sub_packet_t* n_dt, sub_packet_t* o_dt) {
                                                  return (n_dt->received_ts < o_dt->received_ts)?-1:
                                                      ((n_dt->received_ts > o_dt->received_ts)?1:
                                                       0);
                                              }));

    _sub_packet_add_to_received_interval(pub, pid);
    return 1;
}


// Go through all received packets and move those that are ready to
// be dispathed to the ready queue
// Should be called after one or more calls to sub_receive_packet()
// Do not call too often since it is medium expensive on execution.
void sub_process_received_packets(sub_publisher_t* pub, sub_packet_list_t* dispatch_ready)
{
    sub_packet_node_t* node = 0;
    assert(pub);
    
    // Move over all packets that are sequential to the
    // last successfully received packet from the received
    // queue top
    node = sub_packet_list_head(&pub->received_pid);

    // Initialize pub->max_pid_ready if not setup already
    if (node && !pub->max_pid_ready)
        pub->max_pid_ready = node->data->pid - 1;

    while(node) {
        if (pub->max_pid_ready &&
            node->data->pid != pub->max_pid_ready + 1) 
            break;

        // Drop the packet in at the tail of provide dispatch_ready list.
        // Since the pub->received() queue we get the packts from is pre-sorted on pid,
        // we will guarantee that packets in dispatch_ready will be sorted on an ascending pid.
        sub_packet_list_unlink(node);

        // Remove self from ts-sorted receive list.
        sub_packet_list_unlink(node->data->received_ts_entry);

        sub_packet_list_push_tail_node(dispatch_ready, node);
        node = sub_packet_list_head(&pub->received_pid);
        pub->max_pid_ready++;
    }
}
    


void sub_init_publisher(sub_publisher_t* pub)
{
    pub->max_pid_received = 0;
    pub->max_pid_ready = 0;
    sub_packet_list_init(&pub->received_pid, 0, 0, 0);
    sub_packet_list_init(&pub->received_ts, 0, 0, 0);
    sub_pid_interval_list_init(&pub->received_interval, 0, 0, 0);
    return;
}

void sub_reset_publisher(sub_publisher_t* pub,
                          void (*payload_free_cb)(void*, payload_len_t, user_data_t))
{
    sub_packet_t* pack = 0;

    assert(pub);

    // Go through all received packets and wipe them.
    // Do a callback to free the payload, if specified.
    while(sub_packet_list_pop_head(&pub->received_pid, &pack)) {
        sub_packet_list_unlink(pack->received_ts_entry);
        if (payload_free_cb)
            (*payload_free_cb)(pack->payload, pack->payload_len, pack->pkg_user_data);
        _free_pending_packet(pack);
    }

    sub_pid_interval_list_empty(&pub->received_interval);

    return;
}



inline user_data_t sub_packet_user_data(sub_packet_t* pack)
{
    return pack?(pack->pkg_user_data):(user_data_t) { .u64 = 0};
}


// Add the pid of a received packet to the number of
// received packets.
// Return:
// 1 - Interval added to list
// 0 - Existing interval modified
// -1 - Interval collapsed
int _sub_packet_add_to_received_interval(sub_publisher_t* pub, packet_id_t pid)
{
    sub_pid_interval_node_t* inode = 0;
    // Do we have an empty list?

    // Traverse the list from the back, to increase chance of hit, to see if we can fit it anywhere
    inode = sub_pid_interval_list_tail(&pub->received_interval);

    while(inode) {
        // Is pid greater last_pid + 1 for the current node?
        // If so, then we need to add a new interval after the current.
        //
        // Example
        //   intv  intv   intv
        //   1-3   6-10   15-17
        //              ^
        //              13 
        //              pid
        if (pid > inode->data.last_pid + 1) {
            sub_pid_interval_list_insert_after(inode, (sub_pid_interval_t) { .first_pid = pid, .last_pid = pid });
            return 1;
        }

        // Can we tag this on the end of the current interval?
        //
        // Example
        //   intv  intv   intv
        //   1-3   6-10   12-17
        //             ^
        //             11 
        //             pid
        if (inode->data.last_pid + 1 == pid) {
            sub_pid_interval_node_t* inext = 0;
            
            inode->data.last_pid = pid;

            // Can we collapse this interval with the next one?
            // Example:
            // Before
            //   intv  intv   intv
            //   1-3   6-11   12-17
            //  
            // After
            //   intv  intv
            //   1-3   6-17
            //  
            inext = sub_pid_interval_list_next(inode);
            if (inext && inext->data.first_pid - 1 == pid) {
                inode->data.last_pid = inext->data.last_pid;
                sub_pid_interval_list_delete(inext);
                return -1; // We manged to delete one interval
            }
            return 0; // We manged to tack onto the existing intercal.
        }

        // Can we tag this on the beginning of the current interval
        // Can we tag this on the end of the current interval?
        //
        // Example
        //   intv  intv   intv
        //   1-4   6-10   15-17
        //        ^
        //        5 
        //       pid
        if (inode->data.first_pid - 1 == pid) {
            sub_pid_interval_node_t* iprev = 0;

            inode->data.first_pid = pid;

            // Can we collapse this interval with the previous one?
            // Example
            // Before:
            //   intv  intv   intv
            //   1-4   5-10   15-17
            //
            // After
            //   intv   intv
            //   1-10   15-17

            iprev = sub_pid_interval_list_prev(inode);
            if (iprev && iprev->data.last_pid + 1 == pid) {
                inode->data.first_pid = iprev->data.first_pid;
                sub_pid_interval_list_delete(iprev);
                return -1;
            }
            return 0;
        }
        inode = sub_pid_interval_list_prev(inode);
    }

    // If wwe came this far, pid is lesser than first_pid - 1 of the first
    // interval in the list. In this case we need to push a new interval
    // to the beginning of the lsit.
    // This case will also be executed if result is currently empty.
    //
    // Example
    //    intv  intv  intv
    //    3-3   6-10  13-13
    //  ^         
    //  1          
    // pid
    //
    sub_pid_interval_list_push_head(&pub->received_interval, (sub_pid_interval_t) { .first_pid = pid, .last_pid = pid });
    return 1;
}

