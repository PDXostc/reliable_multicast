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

// =============
// SOCKET SLOT MANAGEMENT
// =============

static rmc_connection_index_t _get_free_slot(rmc_context_t* ctx)
{
    rmc_connection_index_t ind = 0;

    while(ind < RMC_MAX_CONNECTIONS) {
        if (ctx->connections[ind].descriptor == -1) {
            if (ctx->max_connection_ind > ind)
                ctx->max_connection_ind = ind;

            return ind;
        }            
        ++ind;
    }

    return -1;
}

static void _reset_max_connection_ind(rmc_context_t* ctx)
{
    rmc_connection_index_t ind = RMC_MAX_CONNECTIONS;

    while(ind--) {
        if (ctx->connections[ind].descriptor != -1) {
            ctx->max_connection_ind = ind;
            return;
        }
    }
    ctx->max_connection_ind = ind;
    return;
}


void rmc_reset_connection(rmc_connection_t* sock, int index)
{
    sock->action = 0;
    sock->rmc_index = index;
    sock->descriptor = -1;
    sock->mode = RMC_CONNECTION_MODE_UNUSED;
    circ_buf_init(&sock->read_buf, sock->read_buf_data, sizeof(sock->read_buf_data));
    circ_buf_init(&sock->write_buf, sock->write_buf_data, sizeof(sock->write_buf_data));
    memset(&sock->remote_address, 0, sizeof(sock->remote_address));
}


// Complete async connect. Called from rmc_write().
int rmc_complete_connect(rmc_context_t* ctx, rmc_connection_t* sock)
{
    rmc_poll_action_t old_action = 0;
    int sock_err = 0;
    socklen_t len = sizeof(sock_err);
    if (!ctx || !sock)
        return EINVAL;
    

    if (getsockopt(sock->descriptor,
                   SOL_SOCKET,
                   SO_ERROR,
                   &sock_err,
                   &len) == -1) {
        printf("rmc_complete_connect(): ind[%d] addr[%s:%d]: getsockopt(): %s\n",
               sock->rmc_index,
               inet_ntoa( (struct in_addr) {
                       .s_addr = htonl(sock->remote_address)
                           }),
               sock->remote_port,
               strerror(errno));
        sock_err = errno; // Save it.
        rmc_close_tcp(ctx, sock->rmc_index);
        return sock_err;
    }

    if (sock_err != 0) {
        printf("rmc_complete_connect(): ind[%d] addr[%s:%d]: %s\n",
               sock->rmc_index,
               inet_ntoa( (struct in_addr) {
                       .s_addr = htonl(sock->remote_address)
                           }),
               sock->remote_port,
               strerror(sock_err));

        if (*ctx->poll_remove)
            (*ctx->poll_remove)(ctx, sock->descriptor, sock->rmc_index);

        rmc_close_tcp(ctx, sock->rmc_index);
        return sock_err;
    }
    
    sock->mode = RMC_CONNECTION_MODE_SUBSCRIBER;
    old_action = sock->action;

    // We are subscribing to data from the publisher, which
    // will resend failed multicast packets via tcp
    sock->mode = RMC_CONNECTION_MODE_SUBSCRIBER;
    sock->action = RMC_POLLREAD;

    // We start off in reading mode
    if (ctx->poll_modify)
        (*ctx->poll_modify)(ctx, sock->descriptor, sock->rmc_index, old_action, sock->action);

    return 0;
}
                               
int rmc_connect_tcp_by_address(rmc_context_t* ctx,
                               uint32_t address,
                               in_port_t port,
                               rmc_connection_index_t* result_index)
{
    rmc_connection_index_t c_ind = -1;
    int res = 0;
    int err = 0;
    struct sockaddr_in sock_addr;

    assert(ctx);

    sock_addr = (struct sockaddr_in) {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = (struct in_addr) { .s_addr = htonl(address) }
    };

    // Find a free slot.
    c_ind = _get_free_slot(ctx);
    if (c_ind == -1)
        return ENOMEM;

    
    ctx->connections[c_ind].descriptor = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

    if (ctx->connections[c_ind].descriptor == -1)
        return errno;
 
    printf("rmc_connect_tcp_by_address(): ind[%d] addr[%s:%d]\n", c_ind, inet_ntoa(sock_addr.sin_addr), ntohs(sock_addr.sin_port));

    
    res = connect(ctx->connections[c_ind].descriptor,
                  (struct sockaddr*) &sock_addr,
                  sizeof(sock_addr));

    if (res == -1 && errno != EINPROGRESS) {
        err = errno; // Errno may be reset by close().
        perror("rmc_connect(): connect()");
        close(ctx->connections[c_ind].descriptor);
        ctx->connections[c_ind].descriptor = -1;
        _reset_max_connection_ind(ctx);
        return 0; // This is not an error, just a failed subscriber setup.
    }
    
    ctx->connections[c_ind].remote_address = address;
    ctx->connections[c_ind].remote_port = port;

    sub_init_publisher(&ctx->connections[c_ind].pubsub.publisher,
                       &ctx->sub_ctx);

    // We are subscribing to data from the publisher, which
    // will resend failed multicast packets via tcp
    ctx->connections[c_ind].mode = RMC_CONNECTION_MODE_CONNECTING;

    // We will get write-ready when connection has been connected.
    ctx->connections[c_ind].action = RMC_POLLWRITE;

    if (ctx->poll_add)
        (*ctx->poll_add)(ctx, ctx->connections[c_ind].descriptor, c_ind, ctx->connections[c_ind].action);

    if (result_index)
        *result_index = c_ind;

    return 0;
}


int rmc_connect_tcp_by_host(rmc_context_t* ctx,
                            char* server_addr,
                            in_port_t port,
                            rmc_connection_index_t* result_index)
{
    struct hostent* host = 0;

    host = gethostbyname(server_addr);
    if (!host)
        return ENOENT;

    return rmc_connect_tcp_by_address(ctx,
                                      ntohl(*(uint32_t*) host->h_addr_list[0]),
                                      port,
                                      result_index);
}




int rmc_process_accept(rmc_context_t* ctx,
                              rmc_connection_index_t* result_index)
{
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    rmc_connection_index_t c_ind = -1;

    // Find a free slot.
    c_ind = _get_free_slot(ctx);

    if (c_ind == -1)
        return ENOMEM;

    ctx->connections[c_ind].descriptor = accept4(ctx->listen_descriptor,
                                             (struct sockaddr*) &src_addr,
                                             &addr_len, SOCK_NONBLOCK);

    if (ctx->connections[c_ind].descriptor == -1)
        return errno;
 
    printf("rmc_process_accept(): %s:%d -> index %d\n",
           inet_ntoa(src_addr.sin_addr), ntohs(src_addr.sin_port), c_ind);


    // The remote end is the subscriber of packets that we pulish
    pub_init_subscriber(&ctx->connections[c_ind].pubsub.subscriber, &ctx->pub_ctx);

    ctx->connections[c_ind].mode = RMC_CONNECTION_MODE_PUBLISHER;
    memcpy(&ctx->connections[c_ind].remote_address, &src_addr.sin_addr.s_addr, sizeof(src_addr.sin_addr.s_addr));

    ctx->connections[c_ind].action = RMC_POLLREAD;
    if (ctx->poll_add)
        (*ctx->poll_add)(ctx,
                         ctx->connections[c_ind].descriptor,
                         c_ind,
                         ctx->connections[c_ind].action);

    if (ctx->poll_modify)  {
        (*ctx->poll_modify)(ctx,
                            ctx->listen_descriptor,
                            RMC_LISTEN_INDEX,
                            RMC_POLLREAD,
                            RMC_POLLREAD);
    }
    
    if (result_index)
        *result_index = c_ind;

    return 0;
}



int rmc_close_tcp(rmc_context_t* ctx, rmc_connection_index_t s_ind)
{
    rmc_connection_t* sock = 0;
    
    // Is s_ind within our connection vector?

    if (s_ind >= RMC_MAX_CONNECTIONS)
        return EINVAL;

    sock = &ctx->connections[s_ind];

    // Are we connected
    if (sock->descriptor == -1)
        return ENOTCONN;
    
    // Shutdown any completed connection.
    if (sock->mode != RMC_CONNECTION_MODE_CONNECTING &&
        shutdown(sock->descriptor, SHUT_RDWR) != 0)
        return errno;

    // Delete from caller's poll vector.
    if (ctx->poll_remove)
        (*ctx->poll_remove)(ctx, sock->descriptor, s_ind);

    if (close(sock->descriptor) != 0)
        return errno;

    rmc_reset_connection(sock, s_ind);

    if (s_ind == ctx->max_connection_ind)
        _reset_max_connection_ind(ctx);

    return 0;
}


int rmc_get_poll_size(rmc_context_t* ctx, int *result)
{
    if (!ctx || !result)
        return EINVAL;

    *result = ctx->connection_count;

    return 0;
}


int rmc_get_poll_vector(rmc_context_t* ctx, rmc_connection_t* result, int* len)
{
    int ind = 0;
    int res_ind = 0;
    int max_len = 0;

    if (!ctx || !result || !len)
        return EINVAL;

    max_len = *len;

    if (ctx->max_connection_ind == -1) {
        *len = 0;
        return 0;
    }

    while(ind < ctx->max_connection_ind && res_ind < max_len) {
        if (ctx->connections[ind].descriptor != -1)
            result[res_ind++] = ctx->connections[ind];

        ind++;
    }

    *len = res_ind;
    return 0;
}
