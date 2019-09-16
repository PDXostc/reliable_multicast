// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)



#include "rmc_internal.h"
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

static int _compare_oldest_unackowledged_packet(rmc_index_t n_ind, rmc_index_t o_ind, void* user_data)
{
    rmc_sub_context_t* ctx = (rmc_sub_context_t*) user_data;
    usec_timestamp_t n_oldest;
    usec_timestamp_t o_oldest;

    n_oldest = sub_oldest_unacknowledged_packet(&ctx->publishers[n_ind]);
    o_oldest = sub_oldest_unacknowledged_packet(&ctx->publishers[o_ind]);

    return (n_oldest < o_oldest)?-1:
        ((n_oldest > o_oldest)?1:0);

}


int rmc_sub_packet_received(rmc_sub_context_t* ctx,
                            rmc_index_t index, // Into ctx->connections and ctx->publishers
                            packet_id_t pid,
                            void* payload,
                            payload_len_t payload_len,
                            usec_timestamp_t current_ts,
                            user_data_t pkg_user_data)
{
    sub_publisher_t* pub = &ctx->publishers[index];


    // If this packet is the first one that needs to be acked for the
    // given publisher, then add the index of the publisher (and
    // connection) into the ctx->pub_ack_list.
    // The list is sorted on oldest unacknowledged packet.
    //
    if (!sub_oldest_unacknowledged_packet(pub))
        rmc_index_list_insert_sorted_rev(&ctx->pub_ack_list,
                                         index,
                                         _compare_oldest_unackowledged_packet,
                                         ctx);

    sub_packet_received(&ctx->publishers[index],
                        pid,
                        payload,
                        payload_len,
                        1, // We want to add this packet to receive interval so that we can ack it.
                        rmc_usec_monotonic_timestamp(),
                        user_data_u32(index));

    return 0;
}

int rmc_sub_get_dispatch_ready_count(rmc_sub_context_t* ctx)
{
    if (!ctx)
        return 0;

    return sub_packet_list_size(&ctx->dispatch_ready);
}

sub_packet_t* rmc_sub_get_next_dispatch_ready(rmc_sub_context_t* ctx)
{
    if (!ctx)
        return 0;

    if (rmc_sub_get_dispatch_ready_count(ctx))
        return sub_packet_list_head(&ctx->dispatch_ready)->data;

    return 0;
}

static int _compare_packet(sub_packet_t* needle, sub_packet_t* haystack, void* user_dat)
{
    return needle == haystack;
}

// Caller still need to free pack->payload
int rmc_sub_packet_dispatched_keep_payload(rmc_sub_context_t* ctx, sub_packet_t* pack)
{
    sub_packet_node_t* node = 0;

    if (!ctx || !pack)
        return EINVAL;

    node = sub_packet_list_find_node(&ctx->dispatch_ready,
                                     pack,
                                     _compare_packet, 0);
    if (!node)
        return ENOENT;

    sub_packet_list_delete(node);

    return 0;
}


// Will free pack->payload
int rmc_sub_packet_dispatched(rmc_sub_context_t* ctx, sub_packet_t* pack)
{
    int res = rmc_sub_packet_dispatched_keep_payload(ctx, pack);

    if (res)
        return res;

    if (ctx->payload_free)
        (*ctx->payload_free)(pack->payload, pack->payload_len, ctx->user_data);
    else
        free(pack->payload);

    return 0;
}

int rmc_sub_packet_interval_acknowledged(rmc_sub_context_t* ctx, rmc_index_t index, sub_pid_interval_t* interval)
{
    rmc_connection_t* conn = 0;

    if (!ctx || ! interval)
        return EINVAL;

    conn = &ctx->conn_vec.connections[index];

    if (!conn || conn->mode != RMC_CONNECTION_MODE_CONNECTED)
        return EINVAL;

    return rmc_sub_write_interval_acknowledgement(ctx, conn, interval);
}



rmc_index_t rmc_sub_packet_index(sub_packet_t* pack)
{
    if (!pack)
        return 0;

    return sub_packet_user_data(pack).u32;
}

payload_len_t rmc_sub_packet_payload_len(sub_packet_t* pack)
{
    if (!pack)
        return 0;

    return pack->payload_len;
}

void* rmc_sub_packet_payload(sub_packet_t* pack)
{
    if (!pack)
        return 0;

    return pack->payload;
}
