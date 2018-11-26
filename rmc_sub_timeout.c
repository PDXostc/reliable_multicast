// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)



#define _GNU_SOURCE
#include "reliable_multicast.h"
#include <errno.h>
#include <stdio.h>


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

    // Go through all publishers with unackowledged packets
    // and process those whose acks are due to be sent.
    //
    inode = rmc_index_list_head(&ctx->pub_ack_list);

    while(inode) {
        sub_publisher_t* pub = &ctx->publishers[inode->data];
        sub_pid_interval_t pid_intv;

        // If it is not yet time to send acks for this publisher, then
        // break out of loop and return.
        if (sub_oldest_unacknowledged_packet(pub) + ctx->ack_timeout > current_ts)
            break;
        
        // For each publisher that we have a timed out ack  for, we will ack
        // all pending packets in one go.
        while(sub_pid_interval_list_pop_head(&pub->received_interval, &pid_intv))
            _rmc_sub_packet_interval_acknowledged(ctx, inode->data, &pid_intv);

        rmc_index_list_delete(inode);
        inode = rmc_index_list_head(&ctx->pub_ack_list);
    }

    return 0;
}


int rmc_sub_timeout_get_next(rmc_sub_context_t* ctx, usec_timestamp_t* result)
{
    usec_timestamp_t oldest_received_ts = 0;
    usec_timestamp_t current_ts = rmc_usec_monotonic_timestamp();
    sub_publisher_t* pub = 0;
    rmc_index_t ind = 0;

    if (!ctx || !result)
        return EINVAL;
    
    // We may not have anything to ack at all.
    if (!rmc_index_list_size(&ctx->pub_ack_list)) {
        *result = -1;
        return 0;
    }

    ind = rmc_index_list_head(&ctx->pub_ack_list)->data;
    pub = &ctx->publishers[ind];

    if (pub->oldest_unacked_ts + ctx->ack_timeout >= current_ts)
        *result = pub->oldest_unacked_ts + ctx->ack_timeout - current_ts;
    else
        *result = 0;

    return 0;
}
