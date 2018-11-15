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
    pub_packet_t *pack;

    if (!ctx || !payload || !payload_len)
        return EINVAL;
    
    pack = pub_next_queued_packet(&ctx->pub_ctx);    
 
   // FIXME: Upper limit to how many packets we can queue before
    //        returning ENOMEM
    pub_queue_packet(&ctx->pub_ctx, payload, payload_len, user_data_ptr(ctx));

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


int rmc_get_dispatch_ready_count(rmc_context_t* ctx)
{
    return sub_get_dispatch_ready_count(&ctx->sub_ctx);
}

sub_packet_t* rmc_get_next_dispatch_ready(rmc_context_t* ctx)
{
    return sub_get_next_dispatch_ready(&ctx->sub_ctx);
}


int rmc_packet_dispatched(rmc_context_t* ctx, sub_packet_t* pack)
{
    rmc_connection_t* conn = sub_packet_user_data(pack).ptr;
    uint16_t old_action = 0;

    if (!conn)
        return EINVAL;
    
    sub_packet_dispatched(pack);

    // If this is the first packet that enters the ack-ready queue,
    // then we need to setup a timeout for when we gather 
    //
//    if (sub_get_acknowledge_ready_count(&ctx->sub_ctx) != 0)
//        ctx->next_send_ack = rmc_usec_monotonic_timestamp() + ctx->ack_timeout;
           
}


int rmc_packet_acknowledged(rmc_context_t* ctx, sub_packet_t* pack)
{
    rmc_connection_t* conn = sub_packet_user_data(pack).ptr;
    ssize_t res = 0;
    uint8_t *seg1 = 0;
    uint32_t seg1_len = 0;
    uint8_t *seg2 = 0;
    uint32_t seg2_len = 0;
    cmd_ack_single_t ack = {
        .packet_id = pack->pid
    };
    uint32_t available = 0;
    uint32_t old_in_use = 0;
    rmc_poll_action_t old_action = 0;

    if (!conn || !ctx || !pack)
        return EINVAL;
    

    conn = sub_packet_user_data(pack).ptr;
    if (conn->mode != RMC_CONNECTION_MODE_SUBSCRIBER)
        return EINVAL;

    sub_packet_acknowledged(pack);

    available = circ_buf_available(&conn->write_buf);
    old_in_use = circ_buf_in_use(&conn->write_buf);
    old_action = conn->action;
    printf("ack(): ctx_id[0x%.8X] pid[%lu] mcast[%s:%d] listen[%s:%d]\n",
           ctx->context_id,
           pack->pid,
           inet_ntoa( (struct in_addr) { .s_addr = htonl(ctx->mcast_group_addr) }),
           ctx->mcast_port,
           inet_ntoa( (struct in_addr) { .s_addr = htonl(conn->remote_address) }),
           conn->remote_port);


    // Allocate memory for command
    circ_buf_alloc(&conn->write_buf, 1,
                   &seg1, &seg1_len,
                   &seg2, &seg2_len);


    *seg1 = RMC_CMD_ACK_SINGLE;

    // Allocate memory for packet header
    circ_buf_alloc(&conn->write_buf, sizeof(ack) ,
                   &seg1, &seg1_len,
                   &seg2, &seg2_len);

    // Copy in packet header
    memcpy(seg1, (uint8_t*) &ack, seg1_len);
    if (seg2_len) 
        memcpy(seg2, ((uint8_t*) &ack) + seg1_len, seg2_len);

    // We always want to read from the tcp  socket.
    conn->action = RMC_POLLREAD;

    // Do we need to arm the write poll descriptor.
    if (!old_in_use) 
        conn->action |= RMC_POLLWRITE;

    if (ctx->poll_modify)
        (*ctx->poll_modify)(ctx,
                            conn->descriptor,
                            conn->connection_index,
                            old_action,
                            conn->action);
    
}


rmc_connection_index_t rmc_sub_packet_connection(sub_packet_t* pack)
{
    rmc_connection_t* conn = 0;
    if (!pack)
        return 0;

    conn = (rmc_connection_t*) sub_packet_user_data(pack).ptr;

    return conn->connection_index;
}
