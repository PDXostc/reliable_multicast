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
    pub_packet_t *pack = pub_next_queued_packet(&ctx->pub_ctx);

    if (!ctx || !payload || !payload_len)
        return EINVAL;
    
    
    // FIXME: Upper limit to how many packets we can queue before
    //        returning ENOMEM
    pub_queue_packet(&ctx->pub_ctx, payload, payload_len);

    if (ctx->poll_modify)  {
        // Did we already have a packet pending for send prior
        // to queueing the lastest packet? If so, old action
        // was POLLWRITE, if not, it was 0.
        (*ctx->poll_modify)(ctx,
                            ctx->mcast_send_descriptor,
                            RMC_MULTICAST_SEND_INDEX,
                            (pack?RMC_POLLWRITE:0),
                            RMC_POLLWRITE);
    }

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
    rmc_connection_t* sock = sub_packet_user_data(pack);

    if (!sock)
        return EINVAL;

    // Check that we are not connecting or are a subscriber.
    // Packets processed by the subscriber prior to the
    // tcp channel back to the publisher having been completed
    // will not be registered by the publisher as unacked
    // since at least one ack is needed over tcp before
    // it starts tracking missing packets.
    //
    if (sock->mode == RMC_CONNECTION_MODE_SUBSCRIBER)
        rmc_proto_ack(ctx, sock, pack);
    
    sub_packet_dispatched(pack);
}
