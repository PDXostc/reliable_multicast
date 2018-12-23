// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#define _GNU_SOURCE 1
#include "reliable_multicast.h"
#include "rmc_log.h"
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/uio.h>


int rmc_conn_process_tcp_write(rmc_connection_t* conn, uint32_t* bytes_left)
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
        RMC_LOG_INFO("writev");
        return errno;
    }

    if (res == 0) { 
        *bytes_left = circ_buf_in_use(&conn->write_buf);
        RMC_LOG_INFO("Failed to send data");
        return 0;
    }

    // We wrote a specific number of bytes, free those
    // bytes from the circular buffer.
    // At the same time grab number of bytes left to
    // send from the buffer.,
    circ_buf_free(&conn->write_buf, res, bytes_left);
    RMC_LOG_DEBUG("Wrote [%ld] bytes", res);

    return 0;
}



// Return EAGAIN if we have a partial command that needs to more data
// to be processed.
// EAGAIN can be returned if one or more commands have been executed
// and it is the last command that is partial.
//
int rmc_conn_process_tcp_read(rmc_connection_vector_t* conn_vec,
                               rmc_index_t s_ind,
                               uint8_t* op_res,
                               rmc_conn_command_dispatch_t* dispatch_table, // Terminated by a null dispatch entry
                               user_data_t user_data)
{
    rmc_connection_t* conn = rmc_conn_find_by_index(conn_vec, s_ind);
    uint32_t in_use = circ_buf_in_use(&conn->read_buf);
    uint8_t command = 0;
    int sock_err = 0;
    socklen_t len = sizeof(sock_err);
    int res;


    // We have at least one byte available since
    // we would not be called w
    res = circ_buf_read(&conn->read_buf, &command, 1, 0);

    if (res) {
        *op_res = RMC_ERROR;
        RMC_LOG_ERROR("Circular buffer read failed: %s", strerror(errno));
        return res;
    }
    
    *op_res = RMC_READ_TCP;
    while(1) {
        rmc_conn_command_dispatch_t* current = dispatch_table;

        // Traverse dispatch table to find matching command byte.
        while(current->dispatch) {
            if (command != current->command) {
                ++current;
                continue;
            }
                
            // The called function will free any additional circular buffer
            // space beyond the command byte.

            // conn->read_buf will still have the command byte as its first byte.
            // It is up to the dispatch function to either return EAGAIN with the buffer
            // untouched, or circ_buf_free the command byte and all of the payload for
            // the command.
            res = (*current->dispatch)(conn, user_data);

            // Not enough data?
            // Roll back the command
            if (res != 0) {
                if (res != EAGAIN) {
                    RMC_LOG_ERROR("Dispatch failed: %s", strerror(errno));
                    *op_res = RMC_ERROR;
                } else
                    RMC_LOG_DEBUG("Dispatch needs more data");

                // We either have a protocol error, or not enough data
                // to process the current packet.
                // In both cases we need to return.
                return res;
            }
            break;
        }

        // No hit in the dispatch table?
        if (!current->dispatch) {
            *op_res = RMC_ERROR;
            RMC_LOG_ERROR("Unknown command byte: %d", command);
            return EPROTO;
        }

        // Read next command byte.
        in_use = circ_buf_in_use(&conn->read_buf);

        // If no data is left, then we are done.
        if (!in_use) {
            return 0;
        }

        // We are at the start of the next command.
        // Read the command byte.
        res = circ_buf_read(&conn->read_buf, &command, 1, 0);
        if (res) {
            RMC_LOG_ERROR("Circular buffer read failed: %s", strerror(errno));
            *op_res = RMC_ERROR;
            return res;
        }
    }
    // Never executed.
    return 0;
}


int rmc_conn_tcp_read(rmc_connection_vector_t* conn_vec,
                       rmc_index_t s_ind,
                       uint8_t* op_res,
                       rmc_conn_command_dispatch_t* dispatch_table, // Terminated by a null dispatch entry
                       user_data_t user_data)
{
    rmc_connection_t* conn = rmc_conn_find_by_index(conn_vec, s_ind);
    ssize_t res = 0;
    uint8_t *seg1 = 0;
    uint32_t seg1_len = 0;
    uint8_t *seg2 = 0;
    uint32_t seg2_len = 0;
    struct iovec iov[2];
    uint32_t available = circ_buf_available(&conn->read_buf);
    uint32_t orig_in_use = circ_buf_in_use(&conn->read_buf);
    int ret = 0;

    *op_res = RMC_READ_TCP;
    if (!available) {
        *op_res = RMC_ERROR;
        return ENOMEM;
    }

    // Grab as much data as we can.
    // The call will only return available
    // data.
    res = circ_buf_alloc(&conn->read_buf,
                         available,
                         &seg1, &seg1_len,
                         &seg2, &seg2_len);

    
    // Did we fail?
    if (res) {
        *op_res = RMC_ERROR;
        return res;
    }

    // Setup a zero-copy scattered socket read
    iov[0].iov_base = seg1;
    iov[0].iov_len = seg1_len;
    iov[1].iov_base = seg2;
    iov[1].iov_len = seg2_len;
    
    errno = 0;
    
    res = readv(conn->descriptor, iov, 2);
    RMC_LOG_DEBUG("read(%d): Wanted %d + %d -> %d bytes. Got %ld %s", 
                  s_ind,
                  seg1_len,
                  seg2_len,
                  seg1_len + seg2_len,
                  res,
                  (res == -1)?strerror(errno):"");

    if (res == -1 || res == 0) {
        *op_res = RMC_READ_DISCONNECT;

        // Give back the memory.
        circ_buf_trim(&conn->read_buf, available);
        return EPIPE;
    }
    
    // Trim the tail end of the allocated data to match the number of
    // bytes read.

    // Trim the end of read_buf so that we ony have our original read_buf data plus
    // the bytes we actually read.
    circ_buf_trim(&conn->read_buf, res + orig_in_use);
    ret = rmc_conn_process_tcp_read(conn_vec, s_ind, op_res,
                                    dispatch_table, user_data);

    return ret;
}
