// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)



#include "reliable_multicast.h"
#include <string.h>
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

static int _process_cmd_ack_single(rmc_connection_t* conn, user_data_t user_data)
{
    cmd_ack_single_t ack;
    rmc_pub_context_t* ctx = (rmc_pub_context_t*) user_data.ptr;

    // Do we have enough data?
    if (circ_buf_in_use(&conn->read_buf) < sizeof(ack))
        return EAGAIN;


    // Read and free.
    circ_buf_read(&conn->read_buf, (uint8_t*) &ack, sizeof(ack), 0);
    circ_buf_free(&conn->read_buf, sizeof(ack), 0);
    printf("_process_cmd_ack_single(): pid[%lu]\n", ack.packet_id);

    // Mark the packet as acknwoledged, and call the payload free function
    // provided to rmc_pub_init_context(). If no function is
    // provided, free() will bre called.
    rmc_pub_packet_ack(ctx, conn, ack.packet_id) ;

    return 0;
}

static int _process_cmd_ack_interval(rmc_connection_t* conn, user_data_t user_data)
{
    cmd_ack_interval_t ack;
    rmc_pub_context_t* ctx = (rmc_pub_context_t*) user_data.ptr;
    packet_id_t pid = 0;
    // Do we have enough data?
    if (circ_buf_in_use(&conn->read_buf) < sizeof(ack))
        return EAGAIN;


    // Read and free.
    circ_buf_read(&conn->read_buf, (uint8_t*) &ack, sizeof(ack), 0);
    circ_buf_free(&conn->read_buf, sizeof(ack), 0);
    printf("_process_cmd_ack_interval(): interval[%lu:%lu]\n", ack.first_pid, ack.last_pid);

    // Mark all packets in the interval as acknwoledged, and call the
    // payload free function provided to rmc_pub_init_context(). If no
    // function is provided, free() will bre called.
    for (pid = ack.first_pid; pid <= ack.last_pid; ++pid)
        rmc_pub_packet_ack(ctx, conn, pid) ;
    return 0;
}

int rmc_pub_close_connection(rmc_pub_context_t* ctx, rmc_index_t s_ind)
{
    
    printf("rmc_pub_close_connection(): index[%d]\n", s_ind);
    _rmc_conn_close_connection(&ctx->conn_vec, s_ind);
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
    rmc_connection_t* conn = 0;
    static rmc_conn_command_dispatch_t dispatch_table[] = {
        { .command = RMC_CMD_ACK_SINGLE, .dispatch = _process_cmd_ack_single },
        { .command = RMC_CMD_ACK_INTERVAL, .dispatch = _process_cmd_ack_interval },
        { .command = 0, .dispatch = 0 }
    };

    if (!ctx)
        return EINVAL;

    if (!op_res)
        op_res = &dummy_res;
    
    if (s_ind == RMC_LISTEN_INDEX)  {
        rmc_connection_t* conn = 0;
        res = _rmc_conn_process_accept(ctx->listen_descriptor, &ctx->conn_vec, &s_ind);

        if (res) {
            *op_res = RMC_ERROR;
            return res;
        }

        // Setup the subscriber struct
        conn = _rmc_conn_find_by_index(&ctx->conn_vec, s_ind);
        assert(conn);
        pub_init_subscriber(&ctx->subscribers[s_ind], &ctx->pub_ctx, user_data_ptr(conn));
        *op_res = RMC_READ_ACCEPT;

        return res;
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
            printf("rmc_pub_read(): recvfrom(MULTICAST): %s\n", strerror(errno));
            *op_res = RMC_ERROR;
            return errno;
        }
        printf("rmc_pub_read(): recvfrom(MULTICAST): Ignored loopback.\n");
        if (ctx->conn_vec.poll_modify)
            (*ctx->conn_vec.poll_modify)(ctx->user_data,
                                         ctx->mcast_send_descriptor,
                                         RMC_MULTICAST_INDEX,
                                         RMC_POLLREAD,
                                         RMC_POLLREAD);
        return 0;
    }

    conn = _rmc_conn_find_by_index(&ctx->conn_vec, s_ind);

    if (!conn) {
        *op_res = RMC_ERROR;

        return ENOTCONN;
    }

    res = _rmc_conn_tcp_read(&ctx->conn_vec, s_ind, op_res,
                             dispatch_table, user_data_ptr(ctx));
    
    if (res == EPIPE) {
        rmc_pub_close_connection(ctx, s_ind);
        return 0; // This is not an error, just regular maintenance.
    }

    // Read poll is always active. Callback to re-arm.
    if (ctx->conn_vec.poll_modify) {
        (*ctx->conn_vec.poll_modify)(ctx->user_data, 
                                     conn->descriptor, 
                                     s_ind, 
                                     RMC_POLLREAD, 
                                     RMC_POLLREAD);
    }
    return res;
}

