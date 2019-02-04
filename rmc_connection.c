// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)



#define _GNU_SOURCE 1
#include "reliable_multicast.h"
#include "rmc_log.h"
#include <string.h>
#include <errno.h>

#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <assert.h>
#include <netinet/tcp.h>

// =============
// SOCKET SLOT MANAGEMENT
// =============
rmc_connection_t* rmc_conn_find_by_address(rmc_connection_vector_t* conn_vec,
                                            uint32_t remote_address,
                                            uint16_t remote_port)
{
    rmc_index_t ind = 0;
//    char want_addr_str[80];
//    char have_addr_str[80];

    // Do we have any connections in use at all?
    if (!conn_vec || conn_vec->max_connection_ind == RMC_NIL_INDEX)
        return 0;

//    strcpy(want_addr_str, inet_ntoa( (struct in_addr) { .s_addr = htonl(remote_address) }));

//    RMC_LOG_DEBUG("ind[%d] max_ind[%d]", ind, conn_vec->max_connection_ind);

    // FIXME: Replace with hash table search to speed up.
    while(ind <= conn_vec->max_connection_ind) {
//        strcpy(have_addr_str, inet_ntoa( (struct in_addr) { .s_addr = htonl(conn_vec->connections[ind].remote_address)}));
//        RMC_LOG_DEBUG("  Want[%s:%d] Have[%s:%d]",
//                      want_addr_str, remote_port,
//                      have_addr_str, conn_vec->connections[ind].remote_port);

        if (conn_vec->connections[ind].descriptor != -1 &&
            remote_address == conn_vec->connections[ind].remote_address &&
            remote_port == conn_vec->connections[ind].remote_port)
            return &conn_vec->connections[ind];

        ++ind;
    }
    return 0;
}

rmc_connection_t* rmc_conn_find_by_index(rmc_connection_vector_t* conn_vec,
                                          rmc_index_t index)
{
    if (!conn_vec)
        return 0;

    // Do we have any connections in use at all?
    if (index >= conn_vec->size)
        return 0;

    if (conn_vec->connections[index].mode == RMC_CONNECTION_MODE_CLOSED)
        return 0;

    return &conn_vec->connections[index];
}


rmc_connection_t* rmc_conn_find_by_node_id(rmc_connection_vector_t* conn_vec,
                                           rmc_node_id_t node_id)
{
    rmc_index_t ind = 0;

    // Do we have any connections in use at all?
    if (!conn_vec || conn_vec->max_connection_ind == RMC_NIL_INDEX)
        return 0;


    // FIXME: Replace with hash table search to speed up.
    while(ind <= conn_vec->max_connection_ind) {
        if (conn_vec->connections[ind].descriptor != -1 &&
            conn_vec->connections[ind].node_id == node_id)
            return &conn_vec->connections[ind];

        ++ind;
    }
    return 0;
}


static rmc_index_t _get_free_slot(rmc_connection_vector_t* conn_vec)
{
    rmc_index_t ind = 0;

    while(ind < conn_vec->size) {
        if (conn_vec->connections[ind].descriptor == -1) {
            if (conn_vec->max_connection_ind < ind ||
                conn_vec->max_connection_ind == RMC_NIL_INDEX)
                conn_vec->max_connection_ind = ind;

            RMC_LOG_DEBUG("Allocating slot %d. max is %d", ind, conn_vec->max_connection_ind);
            return ind;
        }
        ++ind;
    }

    return RMC_NIL_INDEX;
}

static void _reset_max_connection_ind(rmc_connection_vector_t* conn_vec)
{
    rmc_index_t ind = conn_vec->size;

    while(ind--) {
        if (conn_vec->connections[ind].descriptor != -1) {
            conn_vec->max_connection_ind = ind;
            return;
        }
    }
    // No connections left.
    conn_vec->max_connection_ind = RMC_NIL_INDEX;
    return;
}


static void rmc_conn_reset_connection(rmc_connection_t* conn, uint32_t index)
{
    conn->action = 0;
    conn->connection_index = index;
    conn->descriptor = -1;
    conn->node_id = 0;
    conn->mode = RMC_CONNECTION_MODE_CLOSED;
    circ_buf_init(&conn->read_buf, conn->read_buf_data, sizeof(conn->read_buf_data));
    circ_buf_init(&conn->write_buf, conn->write_buf_data, sizeof(conn->write_buf_data));
    memset(&conn->remote_address, 0, sizeof(conn->remote_address));
    conn->remote_port = 0;
}

void rmc_conn_init_connection_vector(rmc_connection_vector_t* conn_vec,
                                      uint8_t* buffer,
                                      uint32_t elem_count,
                                      user_data_t user_data,
                                      rmc_poll_add_cb_t poll_add,
                                      rmc_poll_modify_cb_t poll_modify,
                                      rmc_poll_remove_cb_t poll_remove)
{
    rmc_index_t ind = 0;

    // Translate byte size to element count.
    conn_vec->size = elem_count;
    conn_vec->max_connection_ind = RMC_NIL_INDEX;;
    conn_vec->active_connection_count = 0;
    conn_vec->connections = (rmc_connection_t*) buffer;
    conn_vec->poll_add = poll_add;
    conn_vec->poll_modify = poll_modify;
    conn_vec->poll_remove = poll_remove;
    conn_vec->user_data = user_data;

    ind = conn_vec->size;
    while(ind--)
        rmc_conn_reset_connection(&conn_vec->connections[ind], ind);
}


// Complete async connect. Called from rmc_sub_write().
int rmc_conn_complete_connection(rmc_connection_vector_t* conn_vec,
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
        RMC_LOG_INDEX_WARNING(conn->connection_index, "addr[%s:%d]: getsockopt(): %s",
                              inet_ntoa( (struct in_addr) {
                                      .s_addr = htonl(conn->remote_address)
                                          }),
                              conn->remote_port,
                              strerror(errno));
        sock_err = errno; // Save it.
        rmc_conn_close_connection(conn_vec, conn->connection_index);
        return sock_err;
    }

    RMC_LOG_INDEX_COMMENT(conn->connection_index,
                          "rmc_conn_complete_connection():  addr[%s:%d]: %s",
                          inet_ntoa( (struct in_addr) {.s_addr = htonl(conn->remote_address) }),
                          conn->remote_port,
                          strerror(sock_err));

    if (sock_err != 0) {
        RMC_LOG_INDEX_INFO(conn->connection_index,
                              "rmc_conn_complete_connection(): addr[%s:%d]: getsockopt() failed: %s",
                              inet_ntoa( (struct in_addr) {.s_addr = htonl(conn->remote_address) }),
                              conn->remote_port,
                              strerror(sock_err));

        if (conn_vec->poll_remove)
            (*conn_vec->poll_remove)(conn_vec->user_data, conn->descriptor, conn->connection_index);

        rmc_conn_close_connection(conn_vec, conn->connection_index);

        return sock_err;
    }

    // Disable Nagle algorithm since latency is of essence when we send
    // out acks.
    if (setsockopt( conn->descriptor, IPPROTO_TCP, TCP_NODELAY, (void *)&tr, sizeof(tr))) {
        sock_err = errno;

        RMC_LOG_INDEX_INFO(conn->connection_index,
                              "rmc_conn_complete_connection(): addr[%s:%d]: set() failed: %s",
                              inet_ntoa( (struct in_addr) {.s_addr = htonl(conn->remote_address) }),
                              conn->remote_port,
                              strerror(sock_err));

        if (conn_vec->poll_remove)
            (*conn_vec->poll_remove)(conn_vec->user_data, conn->descriptor, conn->connection_index);

        rmc_conn_close_connection(conn_vec, conn->connection_index);
        return sock_err;
    }

    // We are subscribing to data from the publisher, which
    // will resend failed multicast packets via tcp
    conn->mode = RMC_CONNECTION_MODE_CONNECTED;
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

int rmc_conn_connect_tcp_by_address(rmc_connection_vector_t* conn_vec,
                                    uint32_t address,
                                    in_port_t port,
                                    rmc_node_id_t node_id,
                                    rmc_index_t* result_index)
{
    rmc_index_t c_ind = RMC_NIL_INDEX;
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
    if (c_ind == RMC_NIL_INDEX)
        return ENOMEM;


    conn_vec->connections[c_ind].descriptor = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

    if (conn_vec->connections[c_ind].descriptor == -1)
        return errno;

    RMC_LOG_INDEX_COMMENT(c_ind, "Connecting to control tcp addr[%s:%d]", inet_ntoa(sock_addr.sin_addr), ntohs(sock_addr.sin_port));

    res = connect(conn_vec->connections[c_ind].descriptor,
                  (struct sockaddr*) &sock_addr,
                  sizeof(sock_addr));

    conn_vec->connections[c_ind].remote_address = address;
    conn_vec->connections[c_ind].node_id = node_id;
    if (res == -1 && errno != EINPROGRESS) {
        err = errno; // Errno may be reset by close().
        RMC_LOG_INFO("Failed to connect: %s", strerror(errno));
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

    conn_vec->active_connection_count++;
    return res;
}




int rmc_conn_process_accept(int listen_descriptor,
                             rmc_connection_vector_t* conn_vec,
                             rmc_index_t* result_index)
{
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    rmc_index_t c_ind = -1;
    int tr = 1;
    int sock_err = 0;

    // Find a free slot.
    c_ind = _get_free_slot(conn_vec);

    if (c_ind == RMC_NIL_INDEX)
        return ENOMEM;

    conn_vec->connections[c_ind].descriptor = accept4(listen_descriptor,
                                                      (struct sockaddr*) &src_addr,
                                                      &addr_len, SOCK_NONBLOCK);

    if (conn_vec->connections[c_ind].descriptor == -1)
        return errno;

    RMC_LOG_INDEX_COMMENT(c_ind, "%s:%d assigned to index %d",
                          inet_ntoa(src_addr.sin_addr), ntohs(src_addr.sin_port), c_ind);

    // Disable Nagle algorithm since latency is of essence when we send
    // out acks.
    if (setsockopt(conn_vec->connections[c_ind].descriptor, IPPROTO_TCP, TCP_NODELAY, (void *)&tr, sizeof(tr))) {
        sock_err = errno;
        rmc_conn_close_connection(conn_vec, conn_vec->connections[c_ind].descriptor);
        return sock_err;
    }

    conn_vec->connections[c_ind].mode = RMC_CONNECTION_MODE_CONNECTED;
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

    conn_vec->active_connection_count++;
    return 0;
}



int rmc_conn_close_connection(rmc_connection_vector_t* conn_vec, rmc_index_t s_ind)
{
    rmc_connection_t* conn = 0;

    // Is s_ind within our connection vector?

    if (s_ind >= conn_vec->size)
        return EINVAL;

    conn = &conn_vec->connections[s_ind];

    // Are we connected
    if (conn->mode == RMC_CONNECTION_MODE_CLOSED)
        return ENOTCONN;

    conn->mode = RMC_CONNECTION_MODE_CLOSED;
    // If we are still connecting then just terminate the conneciton.


    RMC_LOG_INDEX_INFO(s_ind,
                       "Closing connection. [%d] bytes will be discarded.",
                       circ_buf_in_use(&conn->write_buf));

    // Ok if this fails due to connection is still
    // in progress of being setup.
    shutdown(conn->descriptor, SHUT_RDWR);

    // Finalize connection shutdown.
    // Delete from caller's poll vector.
    if (conn_vec->poll_remove)
        (*conn_vec->poll_remove)(conn_vec->user_data,
                                 conn->descriptor,
                                 s_ind);

    if (close(conn->descriptor) != 0)
        RMC_LOG_WARNING("Could not close descriptor %d: %s", conn->descriptor, strerror(errno));

    rmc_conn_reset_connection(conn, s_ind);

    if (s_ind == conn_vec->max_connection_ind)
        _reset_max_connection_ind(conn_vec);

    conn_vec->active_connection_count--;

    return 0;
}


int rmc_conn_get_max_index_in_use(rmc_connection_vector_t* conn_vec, rmc_index_t *result)
{
    if (!conn_vec || !result)
        return EINVAL;

    *result = conn_vec->max_connection_ind;
}

int rmc_conn_get_active_connection_count(rmc_connection_vector_t* conn_vec, rmc_index_t *result)
{
    if (!conn_vec || !result)
        return EINVAL;

    *result = conn_vec->active_connection_count;
}


int rmc_conn_get_pending_send_length(rmc_connection_t* conn, payload_len_t* result)
{

    if (!conn || !result)
        return EINVAL;

    *result = circ_buf_in_use(&conn->write_buf);
    return 0;
}

int rmc_conn_get_vector_size(rmc_connection_vector_t* conn_vec, rmc_index_t *result)
{
    if (!conn_vec || !result)
        return EINVAL;

    *result = conn_vec->size;

    return 0;
}
