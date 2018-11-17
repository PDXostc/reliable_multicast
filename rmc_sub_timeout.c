// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)



#define _GNU_SOURCE
#include "rmc_proto.h"
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <memory.h>


int rmc_sub_timeout_process(rmc_sub_context_t* ctx)
{
    usec_timestamp_t ts = rmc_usec_monotonic_timestamp();
    pub_sub_list_t subs;
    pub_subscriber_t* sub = 0;
    int res = 0;
    sub_packet_t* pack = 0;
    
    if (!ctx)
        return EINVAL;


    while((pack = sub_get_next_acknowledge_ready(&ctx->sub_ctx))) {
        rmc_connection_t* conn = 0;
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
    
        conn = sub_packet_user_data(pack).ptr;
        sub_packet_acknowledged(pack);
        if (!conn || conn->mode != RMC_CONNECTION_MODE_SUBSCRIBER)
            continue;

        available = circ_buf_available(&conn->write_buf);
        old_in_use = circ_buf_in_use(&conn->write_buf);
        old_action = conn->action;

        printf("process_packet_ack_timeout(): pid[%lu] mcast[%s:%d] listen[%s:%d]\n",
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
        conn->action |= RMC_POLLWRITE;

        if (ctx->conn_vec.poll_modify)
            (*ctx->conn_vec.poll_modify)(ctx->user_data,
                                         conn->descriptor,
                                         conn->connection_index,
                                         old_action,
                                         conn->action);

    }
    return 0;
}


int rmc_sub_timeout_get_next(rmc_sub_context_t* ctx, usec_timestamp_t* result)
{
    usec_timestamp_t oldest_received_ts = 0;
    usec_timestamp_t current_ts = rmc_usec_monotonic_timestamp();

    if (!ctx || !result)
        return EINVAL;
    

    // Get the timestamp when the oldest packet was received that we haven
    // yet to send an acknowledgement back to the publisher for.
    sub_get_oldest_unacknowledged_packet(&ctx->sub_ctx, &oldest_received_ts);
    
    // Did we have infinite timeout?
    if (oldest_received_ts == -1) {
        *result = -1;
        return 0;
    }
        

    oldest_received_ts = oldest_received_ts + ctx->ack_timeout - current_ts;
    if (oldest_received_ts < 0)
        oldest_received_ts = 0;


    *result = oldest_received_ts;
    return 0;
}
