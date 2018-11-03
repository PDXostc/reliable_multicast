// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)



#define _GNU_SOURCE
#include "rmc_proto.h"
#include <string.h>
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <assert.h>


int rmc_queue_packet(rmc_context_t* ctx,
                     void* payload,
                     payload_len_t payload_len)
{
    rmc_poll_t old_info;

    if (!ctx || !payload || !payload_len)
        return EINVAL;
    
    // FIXME: Upper limit to how many packets we can queue before
    //        returning ENOMEM
    pub_queue_packet(&ctx->pub_ctx, payload, payload_len);

    old_info = ctx->mcast_pinfo;

    ctx->mcast_pinfo.action |= RMC_POLLWRITE;

    if (ctx->poll_modify) 
        (*ctx->poll_modify)(ctx, &old_info, &ctx->mcast_pinfo);

    return 0;
}


int rmc_get_ready_packet_count(rmc_context_t* ctx)
{
    return sub_get_ready_packet_count(&ctx->sub_ctx);
}

sub_packet_t* rmc_get_next_ready_packet(rmc_context_t* ctx)
{
    return sub_get_next_ready_packet(&ctx->sub_ctx);
}

int rmc_free_packet(rmc_context_t* ctx, sub_packet_t* pack)
{
    rmc_socket_t* sock = sub_packet_user_data(pack);

    if (!sock)
        return EINVAL;

    rmc_proto_ack(ctx, sock, pack);
    
    sub_packet_dispatched(pack);
}
