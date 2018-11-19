// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)



#define _GNU_SOURCE
#include "reliable_multicast.h"
#include <string.h>
#include <errno.h>

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


// Queue the packet up for being acked by rmc_proto_timeout.c::_process_packet_ack_timeout()
int rmc_sub_packet_acknowledged(rmc_sub_context_t* ctx, sub_packet_t* pack)
{
    rmc_connection_t* conn = 0;

    if (!ctx || !pack)
        return EINVAL;
    
    conn = sub_packet_user_data(pack).ptr;

    if (conn->mode != RMC_CONNECTION_MODE_SUBSCRIBER)
        return EINVAL;

    sub_packet_acknowledged(pack);

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
