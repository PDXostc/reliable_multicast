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
#include <arpa/inet.h>
#include <assert.h>

// FIXME: If we see timed out (== lost) packets from subscribers, we should
//        switch them to TCP for a period of time in order
//        to use TCP's flow control until congestion has eased.


// =============
// SOCKET WRITE
// =============


int _rmc_sub_write_acknowledgement(rmc_sub_context_t* ctx, sub_packet_t* pack)
{
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
        rmc_connection_t* conn = 0;
        char group_addr[80];
        char remote_addr[80];

        conn = sub_packet_user_data(pack).ptr;

        if (!conn || conn->mode != RMC_CONNECTION_MODE_SUBSCRIBER)
            return ENOTCONN;

        available = circ_buf_available(&conn->write_buf);
        old_in_use = circ_buf_in_use(&conn->write_buf);
        old_action = conn->action;

        strcpy(group_addr, inet_ntoa( (struct in_addr) { .s_addr = htonl(ctx->mcast_group_addr) }));
        strcpy(remote_addr, inet_ntoa( (struct in_addr) { .s_addr = htonl(conn->remote_address) }));
        printf("_rmc_sub_write_acknowledgement(): pid[%lu] mcast[%s:%d] remote[%s:%d]\n",
               pack->pid,
               group_addr,
               ctx->mcast_port,
               remote_addr,
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

int rmc_sub_write(rmc_sub_context_t* ctx, rmc_connection_index_t s_ind, uint8_t* op_res)
{
    int res = 0;
    int rearm_write = 0;
    uint32_t bytes_left_before = 0;
    uint32_t bytes_left_after = 0;
    rmc_poll_action_t old_action;
    rmc_connection_t* conn = 0;

    assert(ctx);

    conn = _rmc_conn_find_by_index(&ctx->conn_vec, s_ind);
    // Is s_ind within our connection vector?
    if (!conn) {
        if (op_res)
            *op_res = RMC_ERROR;

        return ENOTCONN;
    }

    // Is this socket in the process of being connected
    if (conn->mode == RMC_CONNECTION_MODE_CONNECTING) {
        if (op_res)
            *op_res = RMC_COMPLETE_CONNECTION;

        sub_init_publisher(&ctx->publishers[s_ind], &ctx->sub_ctx);
        _rmc_conn_complete_connection(&ctx->conn_vec, conn);
        return 0;
    }

    old_action = conn->action;

    // Do we have any data to write?
    if (circ_buf_in_use(&conn->write_buf) == 0) {
        if (op_res)
            *op_res = RMC_ERROR;

        return ENODATA;
    }

    if (op_res)
        *op_res = RMC_WRITE_TCP;
    
    res = _rmc_conn_process_tcp_write(conn, &bytes_left_after);
    
    if (bytes_left_after == 0) 
        conn->action &= ~RMC_POLLWRITE;
    else
        conn->action |= RMC_POLLWRITE;

    if (ctx->conn_vec.poll_modify)
        (*ctx->conn_vec.poll_modify)(ctx->user_data,
                                     conn->descriptor,
                                     s_ind,
                                     old_action,
                                     conn->action);

    // Did we encounter an error.
    if (res && op_res)
        *op_res = RMC_ERROR;
        
    return res;
}
