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
    return sub_get_dispatch_ready_count(&ctx->sub_ctx);
}

sub_packet_t* rmc_sub_get_next_dispatch_ready(rmc_sub_context_t* ctx)
{
    return sub_get_next_dispatch_ready(&ctx->sub_ctx);
}


int rmc_sub_packet_dispatched(rmc_sub_context_t* ctx, sub_packet_t* pack)
{
    rmc_connection_t* conn = sub_packet_user_data(pack).ptr;
    uint16_t old_action = 0;

    if (!conn)
        return EINVAL;
    
    sub_packet_dispatched(pack);
}


// Called by rmc_sub_process_timeout() to
// feed a packet ack to the tcp stream
int _rmc_sub_packet_acknowledged(rmc_sub_context_t* ctx, sub_packet_t* pack)
{
    rmc_connection_t* conn = 0;

    if (!ctx || !pack)
        return EINVAL;
    
    conn = sub_packet_user_data(pack).ptr;

    if (conn->mode != RMC_CONNECTION_MODE_SUBSCRIBER)
        return EINVAL;

    // Queue up tcp command
    if (!pack->skip_acknowledgement)
        _rmc_sub_write_acknowledgement(ctx, conn, pack->pid);

    sub_packet_acknowledged(pack);

    if (ctx->payload_free)
        (*ctx->payload_free)(pack->payload, pack->payload_len, ctx->user_data);
    else
        free(pack->payload);
    
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
