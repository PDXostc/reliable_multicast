// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)



#define _GNU_SOURCE
#include "reliable_multicast.h"
#include "rmc_log.h"
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int rmc_pub_queue_packet(rmc_pub_context_t* ctx,
                         void* payload,
                         payload_len_t payload_len,
                         uint8_t announce_flag)
{
    pub_packet_t *pack;

    if (!ctx || !payload)
        return EINVAL;
     
    if (payload_len > RMC_MAX_PAYLOAD) {
        RMC_LOG_ERROR("Oversized packet [%d] bytes. Max size[%d]\n", payload_len, RMC_MAX_PAYLOAD);
        return EMSGSIZE;

    }
    pack = pub_next_queued_packet(&ctx->pub_ctx);    
 

    // If this is an announcement, force PID to 0.
    // If this is a regular packet, let pub.c figure out the next PID to use.
    if (announce_flag)
        pub_queue_no_acknowledge_packet(&ctx->pub_ctx, payload, payload_len, user_data_nil());
    else
        pub_queue_packet(&ctx->pub_ctx, payload, payload_len, user_data_nil());

    if (ctx->conn_vec.poll_modify)  {
        // Did we already have a packet pending for send prior
        // to queueing the lastest packet? If so, old action
        // was POLLWRITE, if not, it was 0.
        (*ctx->conn_vec.poll_modify)(ctx->user_data,
                                     ctx->mcast_send_descriptor,
                                     RMC_MULTICAST_INDEX,
                                     (pack?RMC_POLLWRITE:0),
                                     RMC_POLLWRITE);
    }

    return 0;
}


uint32_t rmc_pub_queue_length(rmc_pub_context_t* ctx)
{
    if (!ctx)
        return 0;

    return  pub_queue_size(&ctx->pub_ctx);
}



int rmc_pub_packet_ack(rmc_pub_context_t* ctx, rmc_connection_t* conn, packet_id_t pid)
{
    pub_packet_ack(&ctx->subscribers[conn->connection_index],
                   pid, 
                   lambda(void, (void* payload, payload_len_t payload_len, user_data_t user_data) {
                           if (ctx->payload_free)
                               (*ctx->payload_free)(payload, payload_len, user_data);
                           else
                               free(payload);
                       }));
    return 0;
}

 
