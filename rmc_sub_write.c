// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)


#include "rmc_internal.h"
#include "rmc_log.h"
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


int rmc_sub_write_interval_acknowledgement(rmc_sub_context_t* ctx,
                                           rmc_connection_t* conn,
                                           sub_pid_interval_t* interval)
{
        ssize_t res = 0;
        uint8_t *seg1 = 0;
        uint32_t seg1_len = 0;
        uint8_t *seg2 = 0;
        uint32_t seg2_len = 0;
        cmd_ack_interval_t ack = {
            .first_pid = interval->first_pid,
            .last_pid = interval->last_pid
        };
        uint32_t available = 0;
        rmc_poll_action_t old_action = 0;
        char group_addr[80];
        char remote_addr[80];

        if (!ctx || !conn || !interval)
            return EINVAL;

        if (conn->mode != RMC_CONNECTION_MODE_CONNECTED)
            return ENOTCONN;

        available = circ_buf_available(&conn->write_buf);
        old_action = conn->action;

        strcpy(group_addr, inet_ntoa( (struct in_addr) { .s_addr = htonl(ctx->mcast_group_addr) }));
        strcpy(remote_addr, inet_ntoa( (struct in_addr) { .s_addr = htonl(conn->remote_address) }));

        RMC_LOG_INDEX_COMMENT(conn->connection_index,
                              "interval[%lu:%lu] mcast[%s:%d] remote[%s:%d]",
                              interval->first_pid,
                              interval->last_pid,
                              group_addr,
                              ctx->mcast_port,
                              remote_addr,
                              conn->remote_port);

        if (available < 1 + sizeof(ack)) {
            RMC_LOG_INDEX_WARNING(conn->connection_index,
                                  "Out of circ buf memory sending ack: interval[%lu:%lu] mcast[%s:%d] remote[%s:%d]",
                                  interval->first_pid,
                                  interval->last_pid,
                                  group_addr,
                                  ctx->mcast_port,
                                  remote_addr,
                                  conn->remote_port);
            return ENOMEM;
        }

        // Allocate memory for command
        res = circ_buf_alloc(&conn->write_buf, 1,
                             &seg1, &seg1_len,
                             &seg2, &seg2_len);

        if (res) {
            RMC_LOG_INDEX_ERROR(conn->connection_index,
                                "Out of circ buf memory setting up ack command: interval[%lu:%lu] mcast[%s:%d] remote[%s:%d]",
                                interval->first_pid,
                                interval->last_pid,
                                group_addr,
                                ctx->mcast_port,
                                remote_addr,
                                conn->remote_port);
            return ENOMEM;
        }

        *seg1 = RMC_CMD_ACK_INTERVAL;

        // Allocate memory for packet header
        res = circ_buf_alloc(&conn->write_buf, sizeof(ack) ,
                             &seg1, &seg1_len,
                             &seg2, &seg2_len);


        if (res) {
            RMC_LOG_INDEX_ERROR(conn->connection_index,
                                "Out of circ buf memory setting up ack header: interval[%lu:%lu] mcast[%s:%d] remote[%s:%d]",
                                interval->first_pid,
                                interval->last_pid,
                                group_addr,
                                ctx->mcast_port,
                                remote_addr,
                                conn->remote_port);
            return ENOMEM;
        }

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
        return 0;
}



int rmc_sub_write_control_message(rmc_sub_context_t* ctx,
                                  rmc_connection_t* conn,
                                  void* payload,
                                  payload_len_t payload_len)
{
        ssize_t res = 0;
        uint8_t *seg1 = 0;
        uint32_t seg1_len = 0;
        uint8_t *seg2 = 0;
        uint32_t seg2_len = 0;
        cmd_control_message_t msg = {
            .payload_len = payload_len,
        };
        uint32_t available = 0;
        rmc_poll_action_t old_action = 0;

        if (!ctx || !conn  || !payload || !payload_len)
            return EINVAL;

        if (conn->mode != RMC_CONNECTION_MODE_CONNECTED) {
            RMC_LOG_INDEX_WARNING(conn->connection_index, "Socket not connected. [%d] Cannot write control message.",
                conn->mode);
            return ENOTCONN;
        }

        available = circ_buf_available(&conn->write_buf);

        if (available < 1 + sizeof(cmd_control_message_t) + payload_len + 1) {
            RMC_LOG_INDEX_WARNING(conn->connection_index, "Out of circ buf memory sending ctl message");
            return ENOMEM;
        }

        old_action = conn->action;

        // Allocate memory for command
        res = circ_buf_alloc(&conn->write_buf, 1,
                             &seg1, &seg1_len,
                             &seg2, &seg2_len);

        if (res) {
            RMC_LOG_INDEX_ERROR(conn->connection_index,
                          "Out of circ buf memory setting up ctl message cmd command");
            return ENOMEM;
        }


        *seg1 = RMC_CMD_CONTROL_MESSAGE;

        // Allocate memory for packet header
        res = circ_buf_alloc(&conn->write_buf, sizeof(msg) ,
                             &seg1, &seg1_len,
                             &seg2, &seg2_len);


        if (res) {
            RMC_LOG_INDEX_ERROR(conn->connection_index,
                                "Out of circ buf memory setting up ctl message cmd header");
            return ENOMEM;
        }


        // Copy in packet header
        memcpy(seg1, (uint8_t*) &msg, seg1_len);
        if (seg2_len)
            memcpy(seg2, ((uint8_t*) &msg) + seg1_len, seg2_len);

        // Allocate memory for payload
        res = circ_buf_alloc(&conn->write_buf, payload_len ,
                             &seg1, &seg1_len,
                             &seg2, &seg2_len);

        if (res) {
            RMC_LOG_INDEX_ERROR(conn->connection_index,
                                "Out of circ buf memory setting up ctl message payload");
            return ENOMEM;
        }

        // Copy in packet header
        memcpy(seg1, (uint8_t*) payload, seg1_len);

       if (seg2_len)
            memcpy(seg2, ((uint8_t*) &payload) + seg1_len, seg2_len);


        // We always want to read from the tcp  socket.
        conn->action |= RMC_POLLWRITE;

        if (ctx->conn_vec.poll_modify)
            (*ctx->conn_vec.poll_modify)(ctx->user_data,
                                         conn->descriptor,
                                         conn->connection_index,
                                         old_action,
                                         conn->action);

        RMC_LOG_INDEX_DEBUG(conn->connection_index, "Sent %d bytes as control message to publisher.", payload_len);
        return 0;
}



int rmc_sub_write_control_message_by_address(rmc_sub_context_t* ctx,
                                             uint32_t remote_address,
                                             uint16_t remote_port,
                                             void* payload,
                                             payload_len_t payload_len)
{
    rmc_connection_t* conn = 0;

    if (!ctx  || !payload || !payload_len)
        return EINVAL;

    conn = rmc_conn_find_by_address(&ctx->conn_vec, remote_address, remote_port);


    if (!conn || conn->mode != RMC_CONNECTION_MODE_CONNECTED)
        return ENOTCONN;

    return rmc_sub_write_control_message(ctx, conn, payload, payload_len);
}



int rmc_sub_write_control_message_by_node_id(rmc_sub_context_t* ctx,
                                             rmc_node_id_t node_id,
                                             void* payload,
                                             payload_len_t payload_len)
{
    rmc_connection_t* conn = 0;

    if (!ctx  || !payload || !payload_len)
        return EINVAL;

    conn = rmc_conn_find_by_node_id(&ctx->conn_vec, node_id);

    if (!conn || conn->mode != RMC_CONNECTION_MODE_CONNECTED)
        return ENOTCONN;

    return rmc_sub_write_control_message(ctx, conn, payload, payload_len);
}


int rmc_sub_write(rmc_sub_context_t* ctx, rmc_index_t s_ind, uint8_t* op_res)
{
    int res = 0;
    uint32_t bytes_left_after = 0;
    rmc_poll_action_t old_action;
    rmc_connection_t* conn = 0;

    assert(ctx);

    conn = rmc_conn_find_by_index(&ctx->conn_vec, s_ind);
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

        sub_init_publisher(&ctx->publishers[s_ind]);
        res = rmc_conn_complete_connection(&ctx->conn_vec, conn);
        if (res) {
            RMC_LOG_INDEX_INFO(s_ind, "Failed to complete connection: %s", strerror(errno));
            rmc_conn_close_connection(&ctx->conn_vec, conn->connection_index);
            return res;
        }
        if (ctx->subscription_complete_cb) {
            RMC_LOG_INDEX_DEBUG(s_ind, "Invoking subscription complete callback");
            (*ctx->subscription_complete_cb)(ctx, conn->remote_address, conn->remote_port, conn->node_id);
        }
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

    res = rmc_conn_process_tcp_write(conn, &bytes_left_after);

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
