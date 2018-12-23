// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)



#define _GNU_SOURCE
#include "reliable_multicast.h"
#include "rmc_log.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


// Send all pending acknowledgements that we need to get going.
// We batch them up since we have a greater chance of sending out a single
// interval ack instead of one-by-one acks.
int rmc_sub_timeout_process(rmc_sub_context_t* ctx)
{
    usec_timestamp_t current_ts = rmc_usec_monotonic_timestamp();
    pub_sub_list_t subs;
    pub_subscriber_t* sub = 0;
    int res = 0;
    sub_packet_t* pack = 0;
    sub_pid_interval_list_t intervals;
    sub_pid_interval_t intv;
    rmc_index_node_t *inode = 0;

    if (!ctx)
        return EINVAL;

    RMC_LOG_DEBUG("called");

    // Go through all publishers with unackowledged packets and
    // process those whose acks are due to be sent.
    //
    // The pub_ack_list contains indexes into ctx->publishers
    // and identifies those publishers that need to have their
    // packets acknowledged next.
    //
    // The list is populated by rmc_sub_packet_received() and is sorted
    // on the ascending chronological order in which publishers need to have their
    // packets acknowledged. This means that the head element
    // points out the next publisher that needs at least one of
    // its packets acked once more than ctx->ack_timeout usecs have
    // elapsed since we received it.
    //
    inode = rmc_index_list_head(&ctx->pub_ack_list);

    //
    // Retreive the publisher with the  
   while(inode) {
        sub_publisher_t* pub = &ctx->publishers[inode->data];
        sub_pid_interval_t pid_intv;
        

        // If it is not yet time to send acks for this publisher, then
        // break out of loop and return.
        if (sub_oldest_unacknowledged_packet(pub) + ctx->ack_timeout > current_ts) {
            RMC_LOG_INDEX_COMMENT(inode->data,
                                  "%ld usec until timeout - returning",
                                  sub_oldest_unacknowledged_packet(pub) + ctx->ack_timeout - current_ts);
            break;
        }
        
        RMC_LOG_INDEX_COMMENT(inode->data,
                              "past timeout by [%ld] msec - processing",
                              current_ts - sub_oldest_unacknowledged_packet(pub) + ctx->ack_timeout);

        // For each publisher that we have a timed out ack  for, we will ack
        // all pending packets in one go.
        while(sub_pid_interval_list_pop_head(&pub->received_interval, &pid_intv)) {
            int res = 0;
            res = rmc_sub_packet_interval_acknowledged(ctx, inode->data, &pid_intv);
            if (res) {
                RMC_LOG_INDEX_INFO(inode->data,"Failed to send packet ack: %s", strerror(res));
                return res;
            }
        }
        rmc_index_list_delete(inode);
        inode = rmc_index_list_head(&ctx->pub_ack_list);
    }

    return 0;
}


int rmc_sub_timeout_get_next(rmc_sub_context_t* ctx, usec_timestamp_t* result)
{
    usec_timestamp_t current_ts = rmc_usec_monotonic_timestamp();
    sub_publisher_t* pub = 0;
    rmc_index_t ind = 0;

    if (!ctx || !result)
        return EINVAL;
    
    // We may not have anything to ack at all.
    if (!rmc_index_list_size(&ctx->pub_ack_list)) {
        RMC_LOG_COMMENT("No publishers found with pending timeouts");
        *result = -1;
        return 0;
    }

    pub = &ctx->publishers[rmc_index_list_head(&ctx->pub_ack_list)->data];
           
    *result = sub_oldest_unacknowledged_packet(pub) + ctx->ack_timeout;
    return 0;
}
