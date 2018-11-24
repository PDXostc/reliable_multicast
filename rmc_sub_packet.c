// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)



#include "reliable_multicast.h"
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>



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


// Caller still need to free pack->payload
int rmc_sub_packet_dispatched(rmc_sub_context_t* ctx, sub_packet_t* pack)
{
    sub_packet_node_t* node = 0;

    if (!ctx || !pack)
        return EINVAL;

        
    node = sub_packet_list_find_node_rev(&ctx->dispatch_ready,
                                         pack,
                                         lambda(int, (sub_packet_t* a, sub_packet_t* b) {
                                                 return a == b;
                                             }));

    if (!node)
        return ENOENT;


    sub_packet_list_delete(node);
    return 0;
}


// Called by rmc_sub_process_timeout() to
// write packet acks back to the sender.
int _rmc_sub_single_packet_acknowledged(rmc_sub_context_t* ctx, sub_packet_t* pack)
{
    rmc_connection_t* conn = 0;

    if (!ctx || !pack)
        return EINVAL;
    
    conn = sub_packet_user_data(pack).ptr;

    if (conn->mode != RMC_CONNECTION_MODE_SUBSCRIBER)
        return EINVAL;


    // If we are to write an ack, then do so.
    if (!pack->skip_acknowledgement)
        _rmc_sub_write_single_acknowledgement(ctx, conn, pack->pid);

//    sub_packet_acknowledged(pack);

    if (ctx->payload_free)
        (*ctx->payload_free)(pack->payload, pack->payload_len, ctx->user_data);
    else
        free(pack->payload);
    
    return 0;
}


int _rmc_sub_packet_interval_acknowledged(rmc_sub_context_t* ctx, sub_pid_interval_t interval)
{
    rmc_connection_t* conn = 0;

    if (!ctx)
        return EINVAL;
    
//    conn = sub_packet_user_data(pack).ptr;
    

//    if (conn->mode != RMC_CONNECTION_MODE_SUBSCRIBER)
//        return EINVAL;


    // If we are to write an ack, then do so.
//    if (!pack->skip_acknowledgement)
//        _rmc_sub_write_single_acknowledgement(ctx, conn, pack->pid);

//    sub_packet_acknowledged(pack);

//    if (ctx->payload_free)
//        (*ctx->payload_free)(pack->payload, pack->payload_len, ctx->user_data);
//    else
//        free(pack->payload);
    
    return 0;
}


rmc_connection_index_t rmc_sub_packet_connection(sub_packet_t* pack)
{
    rmc_connection_t* conn = 0;
    if (!pack)
        return 0;

    conn = (rmc_connection_t*) sub_packet_user_data(pack).ptr;

    return conn->connection_index;
}
