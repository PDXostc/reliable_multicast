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

static int _process_cmd_ack_single(rmc_pub_context_t* ctx, rmc_connection_t* conn, payload_len_t len)
{
    cmd_ack_single_t ack;
    if (len < sizeof(ack))
        return EAGAIN;

    circ_buf_read(&conn->read_buf, (uint8_t*) &ack, sizeof(ack), 0);
    circ_buf_free(&conn->read_buf, sizeof(ack), 0);
    printf("Acking[%lu]\n", ack.packet_id);
//    extern void test_print_pub_context(pub_context_t* ctx);
//    test_print_pub_context(&ctx->pub_ctx);
    pub_packet_ack(&conn->pubsub.subscriber,
                   ack.packet_id,
                   lambda(void, (void* payload, payload_len_t payload_len, user_data_t user_data) {
                           if (ctx->payload_free)
                               (*ctx->payload_free)(payload, payload_len, user_data);
                           else
                               free(payload);
                       }));
    return 0;
}

static int _process_cmd_ack_interval(rmc_pub_context_t* ctx, rmc_connection_t* conn, payload_len_t len)
{
    return 0;
}

// Return EAGAIN if we have a partial command that needs to more data
// to be processed.
// EAGAIN can be returned if one or more commands have been executed
// and it is the last command that is partial.
///
static int _process_tcp_read(rmc_pub_context_t* ctx,
                             rmc_connection_index_t s_ind,
                             uint8_t* read_res)
{
    rmc_connection_t* conn = &ctx->conn_vec.connections[s_ind];
    uint32_t in_use = circ_buf_in_use(&conn->read_buf);
    uint8_t command = 0;
    int sock_err = 0;
    socklen_t len = sizeof(sock_err);
    int res;

    // Do we have a command byte?
    if (in_use < 1) {
        if (getsockopt(conn->descriptor,
                       SOL_SOCKET,
                       SO_ERROR,
                       &sock_err,
                       &len) == -1) {
            printf("process_tcp_read(): getsockopt(): %s\n",
                   strerror(errno));
            sock_err = errno; // Save it.
            _rmc_conn_close_connection(&ctx->conn_vec, conn->connection_index);
            return sock_err;
        }
        printf("process_tcp_read(): getsockopt(ok): %s\n",
               strerror(sock_err));
        return sock_err;
    }


    // We have at least one byte available.
    res = circ_buf_read(&conn->read_buf, &command, 1, 0);
    circ_buf_free(&conn->read_buf, 1, &in_use);

    if (res) {
        if (read_res)
            *read_res = RMC_ERROR;
        return res;
    }
    
    if (read_res)
        *read_res = RMC_READ_TCP;
    

    while(1) {
        switch(command) {

        case RMC_CMD_ACK_SINGLE:
            if ((res = _process_cmd_ack_single(ctx, conn, in_use)) != 0)
                return res; // Most likely EAGAIN
            break;

        case RMC_CMD_ACK_INTERVAL:
            if ((res = _process_cmd_ack_interval(ctx, conn, in_use)) != 0)
                return res; // Most likely EAGAIN


        default:
            // FIXME: Disconnect subscriber and report issue.
            return EPROTO;
        }

        in_use = circ_buf_in_use(&conn->read_buf);

        if (!in_use)
            return 0;

        // We are at the start of the next command.
        // Read the command byte.
        res = circ_buf_read(&conn->read_buf, &command, 1, 0);
        if (res)
            return res;

        circ_buf_free(&conn->read_buf, 1, 0);
    }

    return 0;
}


static int _tcp_read(rmc_pub_context_t* ctx, rmc_connection_index_t s_ind, uint8_t* read_res)
{
    rmc_connection_t* conn = &ctx->conn_vec.connections[s_ind];
    ssize_t res = 0;
    uint8_t *seg1 = 0;
    uint32_t seg1_len = 0;
    uint8_t *seg2 = 0;
    uint32_t seg2_len = 0;
    struct iovec iov[2];
    uint32_t available = circ_buf_available(&conn->read_buf);

    // Grab as much data as we can.
    // The call will only return available
    // data.
    circ_buf_alloc(&conn->read_buf,
                   available,
                   &seg1, &seg1_len,
                   &seg2, &seg2_len);

    if (!seg1_len) {
        if (read_res)
            *read_res = RMC_ERROR;
        return ENOMEM;
    }

    // Setup a zero-copy scattered socket write
    iov[0].iov_base = seg1;
    iov[0].iov_len = seg1_len;
    iov[1].iov_base = seg2;
    iov[1].iov_len = seg2_len;
    
    res = readv(conn->descriptor, iov, 2);


    if (res == -1 || res == 0) {
        if (read_res)
            *read_res = RMC_READ_DISCONNECT;

        // Give back the memory.
        circ_buf_trim(&conn->read_buf, available);
        return EPIPE;
    }
    
    // Trim the tail end of the allocated data to match the number of
    // bytes read.
    printf("circ_buf_alloc(): Got %d. Trimming to %ld\n", available, res);
    circ_buf_trim(&conn->read_buf, res);

    return _process_tcp_read(ctx, s_ind, read_res);
    
}

int rmc_pub_read(rmc_pub_context_t* ctx, rmc_connection_index_t s_ind, uint8_t* op_res)
{
    int res = 0;

    if (!ctx)
        return EINVAL;

    if (s_ind == RMC_LISTEN_INDEX)  {

        res = _rmc_conn_process_accept(ctx->listen_descriptor, &ctx->conn_vec, &s_ind);

        if (res && op_res)
            *op_res = RMC_ERROR;

        if (!res && op_res)
            *op_res = RMC_READ_ACCEPT;

        return res;
    }
            
            
    // Is c_ind within our connection vector?
    if (s_ind >= RMC_MAX_CONNECTIONS) {
        if (op_res) 
            *op_res = RMC_ERROR;
        return EINVAL;
    }

    if (ctx->conn_vec.connections[s_ind].descriptor == -1) {
        if (op_res) 
            *op_res = RMC_ERROR;
        return ENOTCONN;
    }

    res = _tcp_read(ctx, s_ind, op_res);

    if (res == EPIPE) {
        _rmc_conn_close_connection(&ctx->conn_vec, s_ind);
        return 0; // This is not an error, just regular maintenance.
    }

    // Read poll is always active. Callback to re-arm.
    if (ctx->conn_vec.poll_modify) {
        (*ctx->conn_vec.poll_modify)(ctx->user_data, 
                                     ctx->conn_vec.connections[s_ind].descriptor, 
                                     s_ind, 
                                     RMC_POLLREAD, 
                                     RMC_POLLREAD);
    }
    return res;
}

