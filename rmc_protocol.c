// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)



#define _GNU_SOURCE 1
#include "reliable_multicast.h"
#include <errno.h>

#include <stdio.h>
#include <sys/uio.h>


int _rmc_conn_process_tcp_write(rmc_connection_t* conn, uint32_t* bytes_left)
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



// Return EAGAIN if we have a partial command that needs to more data
// to be processed.
// EAGAIN can be returned if one or more commands have been executed
// and it is the last command that is partial.
//
int _rmc_conn_process_tcp_read(rmc_connection_vector_t* conn_vec,
                               rmc_connection_index_t s_ind,
                               uint8_t* op_res,
                               rmc_conn_command_dispatch_t* dispatch_table, // Terminated by a null dispatch entry
                               user_data_t user_data)
{
    rmc_connection_t* conn = _rmc_conn_find_by_index(conn_vec, s_ind);
    uint32_t in_use = circ_buf_in_use(&conn->read_buf);
    uint8_t command = 0;
    int sock_err = 0;
    socklen_t len = sizeof(sock_err);
    int res;

    // We have at least one byte available since
    // we would not be called w
    res = circ_buf_read(&conn->read_buf, &command, 1, 0);
    circ_buf_free(&conn->read_buf, 1, &in_use);

    if (res) {
        *op_res = RMC_ERROR;
        return res;
    }
    
    *op_res = RMC_READ_TCP;
    
    while(1) {
        rmc_conn_command_dispatch_t* current = dispatch_table;

        while(current->dispatch) {
            if (command == current->command) {
                // The called function will free any additional circular buffer
                // space beyond the command byte.

                res = (*current->dispatch)(conn, user_data);

                // Not enough data?
                if (res == EAGAIN)
                    return 0;

                if (res != 0) {
                    *op_res = RMC_ERROR;
                    return res;
                }
                break;
            }
            ++current;
        }

        // No hit in the dispatch table?
        if (!current->dispatch) {
            *op_res = RMC_ERROR;
            return EPROTO;
        }

        // Read next command byte.
        in_use = circ_buf_in_use(&conn->read_buf);

        if (!in_use)
            return 0;

        // We are at the start of the next command.
        // Read the command byte.
        res = circ_buf_read(&conn->read_buf, &command, 1, 0);
        if (res) {
            *op_res = RMC_ERROR;
            return res;
        }
        circ_buf_free(&conn->read_buf, 1, 0);
    }

    // Never executed.
    return 0;
}


int _rmc_conn_tcp_read(rmc_connection_vector_t* conn_vec,
                       rmc_connection_index_t s_ind,
                       uint8_t* op_res,
                       rmc_conn_command_dispatch_t* dispatch_table, // Terminated by a null dispatch entry
                       user_data_t user_data)
{
    rmc_connection_t* conn = _rmc_conn_find_by_index(conn_vec, s_ind);
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
        *op_res = RMC_ERROR;
        return ENOMEM;
    }

    // Setup a zero-copy scattered socket write
    iov[0].iov_base = seg1;
    iov[0].iov_len = seg1_len;
    iov[1].iov_base = seg2;
    iov[1].iov_len = seg2_len;
    
    res = readv(conn->descriptor, iov, 2);


    if (res == -1 || res == 0) {
        *op_res = RMC_READ_DISCONNECT;

        // Give back the memory.
        circ_buf_trim(&conn->read_buf, available);
        return EPIPE;
    }
    
    // Trim the tail end of the allocated data to match the number of
    // bytes read.
    printf("circ_buf_alloc(): Got %d. Trimming to %ld\n", available, res);
    circ_buf_trim(&conn->read_buf, res);

    return _rmc_conn_process_tcp_read(conn_vec, s_ind, op_res,
                                      dispatch_table, user_data);
}
