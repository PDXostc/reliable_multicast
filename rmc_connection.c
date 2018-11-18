// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)



#define _GNU_SOURCE 1
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
#include <netinet/tcp.h>

// =============
// SOCKET SLOT MANAGEMENT
// =============

rmc_connection_t* _rmc_conn_find_by_address(rmc_connection_vector_t* conn_vec,
                                            uint32_t remote_address,
                                            uint16_t remote_port)
{
    rmc_connection_index_t ind = 0;
    char want_addr_str[80];
    char have_addr_str[80];

    // Do we have any connections in use at all?
    if (conn_vec->max_connection_ind == -1)
        return 0;
    
    // FIXME: Replace with hash table search to speed up.
    strcpy(want_addr_str, inet_ntoa( (struct in_addr) { .s_addr = htonl(remote_address) }));

//    printf("_find_by_address(): max_connection_ind[%d]\n", conn_vec->max_connection_ind);
    while(ind <= conn_vec->max_connection_ind) {
        strcpy(have_addr_str, inet_ntoa( (struct in_addr) { .s_addr = htonl(conn_vec->connections[ind].remote_address)}));
        
//        printf("_find_by_address(): want[%s:%d] got [%s:%d]\n",
//               want_addr_str, remote_port, have_addr_str, conn_vec->connections[ind].remote_port);

        
        if (conn_vec->connections[ind].descriptor != -1 &&  
            remote_address == conn_vec->connections[ind].remote_address &&
            remote_port == conn_vec->connections[ind].remote_port)
            return &conn_vec->connections[ind];

        ++ind;
    }
    return 0;
}

rmc_connection_t* _rmc_conn_find_by_index(rmc_connection_vector_t* conn_vec,
                                          rmc_connection_index_t index)
{
    if (!conn_vec)
        return 0;

    // Do we have any connections in use at all?
    if (index >= conn_vec->size)
        return 0;

    if (conn_vec->connections[index].descriptor == -1)
        return 0;

    return &conn_vec->connections[index];
}

static rmc_connection_index_t _get_free_slot(rmc_connection_vector_t* conn_vec)
{
    rmc_connection_index_t ind = 0;

    while(ind < RMC_MAX_CONNECTIONS) {
        if (conn_vec->connections[ind].descriptor == -1) {
            if (conn_vec->max_connection_ind > ind)
                conn_vec->max_connection_ind = ind;

            return ind;
        }            
        ++ind;
    }

    return -1;
}

static void _reset_max_connection_ind(rmc_connection_vector_t* conn_vec)
{
    rmc_connection_index_t ind = RMC_MAX_CONNECTIONS;

    while(ind--) {
        if (conn_vec->connections[ind].descriptor != -1) {
            conn_vec->max_connection_ind = ind;
            return;
        }
    }
    conn_vec->max_connection_ind = ind;
    return;
}


static void _rmc_conn_reset_connection(rmc_connection_t* conn, uint32_t index)
{
    conn->action = 0;
    conn->connection_index = index;
    conn->descriptor = -1;
    conn->mode = RMC_CONNECTION_MODE_UNUSED;
    circ_buf_init(&conn->read_buf, conn->read_buf_data, sizeof(conn->read_buf_data));
    circ_buf_init(&conn->write_buf, conn->write_buf_data, sizeof(conn->write_buf_data));
    memset(&conn->remote_address, 0, sizeof(conn->remote_address));
}

void _rmc_conn_init_connection_vector(rmc_connection_vector_t* conn_vec,
                                      uint8_t* buffer,
                                      uint32_t elem_count,
                                      user_data_t user_data,
                                      rmc_poll_add_cb_t poll_add,
                                      rmc_poll_modify_cb_t poll_modify,
                                      rmc_poll_remove_cb_t poll_remove)
{
    uint32_t ind = 0;
    
    // Translate byte size to element count.
    conn_vec->size = elem_count;
    conn_vec->max_connection_ind = -1;
    conn_vec->connection_count = 0;
    conn_vec->connections = (rmc_connection_t*) buffer;
    conn_vec->poll_add = poll_add;
    conn_vec->poll_modify = poll_modify;
    conn_vec->poll_remove = poll_remove;
    conn_vec->user_data = user_data;

    ind = conn_vec->size;
    while(ind--) 
        _rmc_conn_reset_connection(&conn_vec->connections[ind], ind);
}


// Complete async connect. Called from rmc_write().
int _rmc_conn_complete_connection(rmc_connection_vector_t* conn_vec,
                                  rmc_connection_t* conn)
{
    rmc_poll_action_t old_action = 0;
    int sock_err = 0;
    socklen_t len = sizeof(sock_err);
    int tr = 1;
    if (!conn_vec || !conn)
        return EINVAL;
    

    if (getsockopt(conn->descriptor,
                   SOL_SOCKET,
                   SO_ERROR,
                   &sock_err,
                   &len) == -1) {
        printf("_rmc_conn_complete_connection(): ind[%d] addr[%s:%d]: getsockopt(): %s\n",
               conn->connection_index,
               inet_ntoa( (struct in_addr) {
                       .s_addr = htonl(conn->remote_address)
                           }),
               conn->remote_port,
               strerror(errno));
        sock_err = errno; // Save it.
        _rmc_conn_close_connection(conn_vec, conn->connection_index);
        return sock_err;
    }

    printf("_rmc_conn_complete_connection(): ind[%d] addr[%s:%d]: %s\n",
           conn->connection_index,
           inet_ntoa( (struct in_addr) {.s_addr = htonl(conn->remote_address) }),
           conn->remote_port,
           strerror(sock_err));

    if (sock_err != 0 && conn_vec->poll_remove) {
        (*conn_vec->poll_remove)(conn_vec->user_data, conn->descriptor, conn->connection_index);

        _rmc_conn_close_connection(conn_vec, conn->connection_index);
        return sock_err;
    }
    
    // Disable Nagle algorithm since latency is of essence when we send
    // out acks.
    if (setsockopt( conn->descriptor, IPPROTO_TCP, TCP_NODELAY, (void *)&tr, sizeof(tr))) {
        sock_err = errno;
        _rmc_conn_close_connection(conn_vec, conn->connection_index);
        return sock_err;
    }

    // We are subscribing to data from the publisher, which
    // will resend failed multicast packets via tcp
    conn->mode = RMC_CONNECTION_MODE_SUBSCRIBER;
    old_action = conn->action;
    conn->action = RMC_POLLREAD;

    // We start off in reading mode
    if (conn_vec->poll_modify)
        (*conn_vec->poll_modify)(conn_vec->user_data,
                                 conn->descriptor,
                                 conn->connection_index,
                                 old_action,
                                 conn->action);

    return 0;
}
                               
int _rmc_conn_connect_tcp_by_address(rmc_connection_vector_t* conn_vec,
                                     uint32_t address,
                                     in_port_t port,
                                     rmc_connection_index_t* result_index)
{
    rmc_connection_index_t c_ind = -1;
    int res = 0;
    int err = 0;
    struct sockaddr_in sock_addr;

    assert(conn_vec);

    sock_addr = (struct sockaddr_in) {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = (struct in_addr) { .s_addr = htonl(address) }
    };

    // Find a free slot.
    c_ind = _get_free_slot(conn_vec);
    if (c_ind == -1)
        return ENOMEM;

    
    conn_vec->connections[c_ind].descriptor = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

    if (conn_vec->connections[c_ind].descriptor == -1)
        return errno;
 
    printf("rmc_connect_tcp_by_address(): ind[%d] addr[%s:%d]\n", c_ind, inet_ntoa(sock_addr.sin_addr), ntohs(sock_addr.sin_port));

    
    res = connect(conn_vec->connections[c_ind].descriptor,
                  (struct sockaddr*) &sock_addr,
                  sizeof(sock_addr));

    if (res == -1 && errno != EINPROGRESS) {
        err = errno; // Errno may be reset by close().
        perror("rmc_connect(): connect()");
        close(conn_vec->connections[c_ind].descriptor);
        conn_vec->connections[c_ind].descriptor = -1;
        _reset_max_connection_ind(conn_vec);
        return 0; // This is not an error, just a failed subscriber setup.
    }
    
    // Nil out the in progress error.
    res = (errno == EINPROGRESS)?0:errno;


    conn_vec->connections[c_ind].remote_address = address;
    conn_vec->connections[c_ind].remote_port = port;

    // We are subscribing to data from the publisher, which
    // will resend failed multicast packets via tcp
    conn_vec->connections[c_ind].mode = RMC_CONNECTION_MODE_CONNECTING;

    // We will get write-ready when connection has been connected.
    conn_vec->connections[c_ind].action = RMC_POLLWRITE;

    // Do callback if defined
    if (conn_vec->poll_add)
        (*conn_vec->poll_add)(conn_vec->user_data,
                              conn_vec->connections[c_ind].descriptor,
                              c_ind,
                              conn_vec->connections[c_ind].action);

    if (result_index)
        *result_index = c_ind;

    return res;
}


int _rmc_conn_connect_tcp_by_host(rmc_connection_vector_t* conn_vec,
                                  char* server_addr,
                                  in_port_t port,
                                  rmc_connection_index_t* result_index)
{
    struct hostent* host = 0;

    host = gethostbyname(server_addr);
    if (!host)
        return ENOENT;

    return _rmc_conn_connect_tcp_by_address(conn_vec,
                                            ntohl(*(uint32_t*) host->h_addr_list[0]),
                                            port,
                                            result_index);
}




int _rmc_conn_process_accept(int listen_descriptor,
                             rmc_connection_vector_t* conn_vec,
                             rmc_connection_index_t* result_index)
{
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    rmc_connection_index_t c_ind = -1;

    // Find a free slot.
    c_ind = _get_free_slot(conn_vec);

    if (c_ind == -1)
        return ENOMEM;

    conn_vec->connections[c_ind].descriptor = accept4(listen_descriptor,
                                                      (struct sockaddr*) &src_addr,
                                                      &addr_len, SOCK_NONBLOCK);

    if (conn_vec->connections[c_ind].descriptor == -1)
        return errno;
 
    printf("rmc_process_accept(): %s:%d -> index %d\n",
           inet_ntoa(src_addr.sin_addr), ntohs(src_addr.sin_port), c_ind);

    conn_vec->connections[c_ind].mode = RMC_CONNECTION_MODE_PUBLISHER;
    conn_vec->connections[c_ind].remote_address = src_addr.sin_addr.s_addr;

    conn_vec->connections[c_ind].action = RMC_POLLREAD;
    if (conn_vec->poll_add)
        (*conn_vec->poll_add)(conn_vec->user_data,
                              conn_vec->connections[c_ind].descriptor,
                              c_ind,
                              conn_vec->connections[c_ind].action);

    if (conn_vec->poll_modify)  
        (*conn_vec->poll_modify)(conn_vec->user_data,
                                 listen_descriptor,
                                 RMC_LISTEN_INDEX,
                                 RMC_POLLREAD,
                                 RMC_POLLREAD);
    
    if (result_index)
        *result_index = c_ind;

    return 0;
}



int _rmc_conn_close_connection(rmc_connection_vector_t* conn_vec, rmc_connection_index_t s_ind)
{
    rmc_connection_t* conn = 0;
    
    // Is s_ind within our connection vector?

    if (s_ind >= RMC_MAX_CONNECTIONS)
        return EINVAL;

    conn = &conn_vec->connections[s_ind];

    // Are we connected
    if (conn->descriptor == -1)
        return ENOTCONN;
    
    // Shutdown any completed connection.
    if (conn->mode != RMC_CONNECTION_MODE_CONNECTING &&
        shutdown(conn->descriptor, SHUT_RDWR) != 0)
        return errno;

    // Delete from caller's poll vector.
    if (conn_vec->poll_remove)
        (*conn_vec->poll_remove)(conn_vec->user_data,
                                 conn->descriptor,
                                 s_ind);

    if (close(conn->descriptor) != 0)
        return errno;

    _rmc_conn_reset_connection(conn, s_ind);

    if (s_ind == conn_vec->max_connection_ind)
        _reset_max_connection_ind(conn_vec);

    return 0;
}


int rmc_conn_get_poll_size(rmc_connection_vector_t* conn_vec, int *result)
{
    if (!conn_vec || !result)
        return EINVAL;

    *result = conn_vec->connection_count;

    return 0;
}


int rmc_conn_get_poll_vector(rmc_connection_vector_t* conn_vec, rmc_connection_t* result, int* len)
{
    int ind = 0;
    int res_ind = 0;
    int max_len = 0;

    if (!conn_vec || !result || !len)
        return EINVAL;

    max_len = *len;

    if (conn_vec->max_connection_ind == -1) {
        *len = 0;
        return 0;
    }

    while(ind < conn_vec->max_connection_ind && res_ind < max_len) {
        if (conn_vec->connections[ind].descriptor != -1)
            result[res_ind++] = conn_vec->connections[ind];

        ind++;
    }

    *len = res_ind;
    return 0;
}


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
