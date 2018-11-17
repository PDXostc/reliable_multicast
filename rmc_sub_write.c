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

// FIXME: If we see timed out (== lost) packets from subscribers, we should
//        switch them to TCP for a period of time in order
//        to use TCP's flow control until congestion has eased.


// =============
// SOCKET WRITE
// =============

static int _process_tcp_write(rmc_sub_context_t* ctx, rmc_connection_t* conn, uint32_t* bytes_left)
{
    uint8_t *seg1 = 0;
    uint32_t seg1_len = 0;
    uint8_t *seg2 = 0;
    uint32_t seg2_len = 0;
    struct iovec iov[2];
    ssize_t res = 0;


    // Grab as much data as we can.
    // The call will only return available
    // data.
    circ_buf_read_segment(&conn->write_buf,
                          sizeof(conn->write_buf_data),
                          &seg1, &seg1_len,
                          &seg2, &seg2_len);

    if (!seg1_len) {
        *bytes_left = 0;
        return ENODATA;
    }
    
    // Setup a zero-copy scattered socket write
    iov[0].iov_base = seg1;
    iov[0].iov_len = seg1_len;
    iov[1].iov_base = seg2;
    iov[1].iov_len = seg2_len;

    errno = 0;
    res = writev(conn->descriptor, iov, seg2_len?2:1);

    // How did that write go?
    if (res == -1) { 
        *bytes_left = circ_buf_in_use(&conn->write_buf);
        return errno;
    }

    if (res == 0) { 
        *bytes_left = circ_buf_in_use(&conn->write_buf);
        return 0;
    }

    // We wrote a specific number of bytes, free those
    // bytes from the circular buffer.
    // At the same time grab number of bytes left to
    // send from the buffer.,
    circ_buf_free(&conn->write_buf, res, bytes_left);

    return 0;
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
    
    res = _process_tcp_write(ctx, conn, &bytes_left_after);
    
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
