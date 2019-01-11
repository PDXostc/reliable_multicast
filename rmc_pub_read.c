// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)



#include "reliable_multicast.h"
#include "rmc_log.h"
#include <string.h>
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>


static int process_cmd_ack_interval(rmc_connection_t* conn, user_data_t user_data)
{
    cmd_ack_interval_t ack;
    rmc_pub_context_t* ctx = (rmc_pub_context_t*) user_data.ptr;
    packet_id_t pid = 0;
    // Do we have enough data?
    if (circ_buf_in_use(&conn->read_buf) < sizeof(ack) + 1)
        return EAGAIN;


    // Read and free.
    circ_buf_read_offset(&conn->read_buf, 1, (uint8_t*) &ack, sizeof(ack), 0);
    circ_buf_free(&conn->read_buf, sizeof(ack) + 1, 0);
    RMC_LOG_INDEX_COMMENT(conn->connection_index,
                          "process_cmd_ack_interval(): interval[%lu:%lu]", ack.first_pid, ack.last_pid);

    // Mark all packets in the interval as acknwoledged, and call the
    // payload free function provided to rmc_pub_init_context(). If no
    // function is provided, free() will bre called.
    for (pid = ack.first_pid; pid <= ack.last_pid; ++pid)
        rmc_pub_packet_ack(ctx, conn, pid) ;
    return 0;
}


int rmc_pub_close_connection(rmc_pub_context_t* ctx, rmc_index_t s_ind)
{
    rmc_connection_t* conn = 0;
    
    if (!ctx)
        return EINVAL;

    conn = rmc_conn_find_by_index(&ctx->conn_vec, s_ind);

    if (!conn)
        return EINVAL;

    if (conn->mode == RMC_CONNECTION_MODE_CLOSED)
        return ENOTCONN;

    // Disconnect callback, if specified through
    // rmc_pub_set_subscriber_connect_callback().
    if (ctx->subscriber_disconnect_cb) {
        (*ctx->subscriber_disconnect_cb)(ctx, conn->remote_address, conn->remote_port);
    }

    rmc_conn_close_connection(&ctx->conn_vec, s_ind);

    RMC_LOG_INDEX_INFO(s_ind, "rmc_pub_close_connection() - ok");
    pub_reset_subscriber(&ctx->subscribers[s_ind],
                         lambda(void, (void* payload, payload_len_t payload_len, user_data_t user_data) {
                                 if (ctx->payload_free)
                                     (*ctx->payload_free)(payload, payload_len, user_data);
                                 else
                                     free(payload);
                             }));
}

int rmc_pub_read(rmc_pub_context_t* ctx, rmc_index_t s_ind, uint8_t* op_res)
{
    int res = 0;
    uint8_t dummy_res = 0;
    payload_len_t write_buf_sz = 0;
    rmc_connection_t* conn = 0;
    rmc_poll_action_t old_action = 0;

    static rmc_conn_command_dispatch_t dispatch_table[] = {
        { .command = RMC_CMD_ACK_INTERVAL, .dispatch = process_cmd_ack_interval },
        { .command = 0, .dispatch = 0 }
    };

    if (!ctx)
        return EINVAL;

    if (!op_res)
        op_res = &dummy_res;
    
    if (s_ind == RMC_LISTEN_INDEX)  {
        rmc_connection_t* conn = 0;
        res = rmc_conn_process_accept(ctx->listen_descriptor, &ctx->conn_vec, &s_ind);


        if (res) {
            *op_res = RMC_ERROR;
            return res;
        }

        // Setup the subscriber struct
        conn = rmc_conn_find_by_index(&ctx->conn_vec, s_ind);


        assert(conn);
        pub_init_subscriber(&ctx->subscribers[s_ind], &ctx->pub_ctx, user_data_ptr(conn));
        *op_res = RMC_READ_ACCEPT;
        // Check if we should accept subscriber
        if (ctx->subscriber_connect_cb) {
            RMC_LOG_COMMENT("Invoking callback for new subscriber connection");
            if (!(*ctx->subscriber_connect_cb)(ctx, conn->remote_address, conn->remote_port))
                rmc_pub_close_connection(ctx, s_ind);
        }

        return 0;
    }
            
    if (s_ind == RMC_MULTICAST_INDEX)  {
        uint8_t throw_away; // Read only one byte of packet, rest will be discarded by kernel
        struct sockaddr_in src_addr;
        socklen_t addr_len = sizeof(src_addr);
        ssize_t len = 0;

        if (ctx->mcast_send_descriptor == -1) {
            *op_res = RMC_ERROR;
            return ENOTCONN;
        }

        errno = 0;
        len = recvfrom(ctx->mcast_send_descriptor,
                       &throw_away, 1, 0,
                       (struct sockaddr*) &src_addr, &addr_len);

        if (len == -1) {
            RMC_LOG_INDEX_WARNING(RMC_MULTICAST_INDEX, "recvfrom(): %s", strerror(errno));
            *op_res = RMC_ERROR;
            return errno;
        }
        RMC_LOG_INDEX_INFO(RMC_MULTICAST_INDEX, "recvfrom(MULTICAST): Ignored loopback");
        if (ctx->conn_vec.poll_modify)
            (*ctx->conn_vec.poll_modify)(ctx->user_data,
                                         ctx->mcast_send_descriptor,
                                         RMC_MULTICAST_INDEX,
                                         RMC_POLLREAD,
                                         RMC_POLLREAD);
        return 0;
    }

    conn = rmc_conn_find_by_index(&ctx->conn_vec, s_ind);

    if (!conn || conn->mode != RMC_CONNECTION_MODE_CONNECTED) {
        *op_res = RMC_ERROR;
        return ENOTCONN;
    }

    res = rmc_conn_tcp_read(&ctx->conn_vec, s_ind, op_res,
                             dispatch_table, user_data_ptr(ctx));
    
    // rmc_conn_tcp_read will return EPIPE if we get
    // zero bytes in a read (happens after we issued a close).
    // or read return -1. In both cases we close the conneciton.
    if (res == EPIPE) { 
        RMC_LOG_INDEX_COMMENT(s_ind, "tcp read returned EPIPE");
        rmc_pub_close_connection(ctx, s_ind);
        return 0; // This is not an error, just regular maintenance.
    }

    // Read poll is always active. Callback to re-arm.
    old_action = conn->action;
    rmc_conn_get_pending_send_length(conn, &write_buf_sz);

    conn->action = RMC_POLLREAD | ((write_buf_sz > 0)?RMC_POLLWRITE:0);

    if (ctx->conn_vec.poll_modify) 
        (*ctx->conn_vec.poll_modify)(ctx->user_data, 
                                     conn->descriptor, 
                                     s_ind, 
                                     old_action,
                                     conn->action);

    return res;
}

int rmc_pub_context_has_pending_send(rmc_pub_context_t* ctx, rmc_index_t s_ind)
{
    rmc_connection_t* conn = 0;
    payload_len_t len = 0;
    
    if (!ctx)
        EINVAL;

    conn = rmc_conn_find_by_index(&ctx->conn_vec, s_ind);
    if (!conn)
        return ENOTCONN;
    
    // Check send buffer.
    rmc_conn_get_pending_send_length(conn, &len);

    if (len > 0)
        return EBUSY;

    return 0;
}
