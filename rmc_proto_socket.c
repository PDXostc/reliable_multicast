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

static int _get_free_slot(rmc_context_t* ctx)
{
    int i = 2; // First two slots are pre-allocated for multicast and listen

    while(i < RMC_MAX_SOCKETS) {
        if (ctx->sockets[i].descriptor == -1) {
            if (ctx->max_socket_ind > i)
                ctx->max_socket_ind = i;

            return i;
        }            
        ++i;
    }
    return -1;
}

static void _reset_max_socket_ind(rmc_context_t* ctx)
{
    int ind = RMC_MAX_SOCKETS;

    while(ind) {
        if (ctx->sockets[ind].descriptor != -1) {
            ctx->max_socket_ind = ind;
            return;
        }
    }
    ctx->max_socket_ind = -1;
}


void rmc_reset_socket(rmc_socket_t* sock, int index)
{
    sock->poll_info.action = 0;
    sock->poll_info.rmc_index = index;
    sock->descriptor = -1;
    sock->mode = RMC_SOCKET_MODE_UNUSED;
    circ_buf_init(&sock->read_buf, sock->read_buf_data, sizeof(sock->read_buf_data));
    circ_buf_init(&sock->write_buf, sock->write_buf_data, sizeof(sock->write_buf_data));
    memset(&sock->remote_address, 0, sizeof(sock->remote_address));
}

int rmc_connect_tcp_by_address(rmc_context_t* ctx,
                               struct sockaddr_in* sock_addr,
                               rmc_poll_index_t* result_index)
{
    rmc_poll_index_t c_ind = -1;

    assert(ctx);
    assert(sock_addr);

    // Find a free slot.
    c_ind = _get_free_slot(ctx);
    if (c_ind == -1)
        return ENOMEM;

    ctx->sockets[c_ind].descriptor = socket (AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

    if (ctx->sockets[c_ind].descriptor == -1)
        return errno;
 
    ctx->sockets[c_ind].poll_info.action = RMC_POLLREAD;

    if (connect(ctx->sockets[c_ind].descriptor,
                (struct sockaddr*) sock_addr,
                sizeof(*sock_addr))) {
        perror("rmc_connect():connect()");
        return errno;
    }

    // We are subscribing to data from the publisher, which
    // will resend failed multicast packets via tcp
    ctx->sockets[c_ind].mode = RMC_SOCKET_MODE_SUBSCRIBER;
    
    sub_init_publisher(&ctx->sockets[c_ind].pubsub.publisher,
                       &ctx->sub_ctx,
                       &ctx->sockets[c_ind]);

    memcpy(&ctx->sockets[c_ind].remote_address, sock_addr, sizeof(*sock_addr));

    if (ctx->poll_add)
        (*ctx->poll_add)(&ctx->sockets[c_ind].poll_info, ctx->user_data);

    if (result_index)
        *result_index = c_ind;

    return 0;
}


int rmc_connect_tcp_by_host(rmc_context_t* ctx,
                            char* server_addr,
                            rmc_poll_index_t* result_index)
{
    struct hostent* host = 0;
    struct sockaddr_in sock_addr;

    host = gethostbyname(server_addr);
    if (!host)
        return ENOENT;

    memcpy((void *) &sock_addr.sin_addr.s_addr,
           (void*) host->h_addr_list[0],
           host->h_length);

    sock_addr.sin_port = htons(ctx->port);
    sock_addr.sin_family = AF_INET;

    return rmc_connect_tcp_by_address(ctx,
                                      &sock_addr,
                                      result_index);
}




int rmc_process_accept(rmc_context_t* ctx,
                              rmc_poll_index_t* result_index)
{
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    rmc_poll_index_t c_ind = -1;

    // Find a free slot.
    c_ind = _get_free_slot(ctx);
    if (c_ind == -1)
        return ENOMEM;

    ctx->sockets[c_ind].descriptor = accept4(ctx->sockets[RMC_LISTEN_SOCKET_INDEX].descriptor,
                                             (struct sockaddr*) &src_addr,
                                             &addr_len, SOCK_NONBLOCK);

    if (ctx->sockets[c_ind].descriptor == -1)
        return errno;


    // The remote end is the subscriber of packets that we pulish
    pub_init_subscriber(&ctx->sockets[c_ind].pubsub.subscriber, &ctx->pub_ctx, &ctx->sockets[c_ind]);

    ctx->sockets[c_ind].mode = RMC_SOCKET_MODE_PUBLISHER;
    memcpy(&ctx->sockets[c_ind].remote_address, &src_addr, sizeof(src_addr));

    ctx->sockets[c_ind].poll_info.action = RMC_POLLREAD;
    if (ctx->poll_add)
        (*ctx->poll_add)(&ctx->sockets[c_ind].poll_info, ctx->user_data);

    if (result_index)
        *result_index = c_ind;

    return 0;
}




int rmc_close_tcp(rmc_context_t* ctx, rmc_poll_index_t p_ind)
{

    // Is p_ind within our socket vector?
    if (p_ind < 2 || p_ind >= RMC_MAX_SOCKETS)
        return EINVAL;

    if (ctx->sockets[p_ind].descriptor == -1)
        return ENOTCONN;

    if (shutdown(ctx->sockets[p_ind].descriptor, SHUT_RDWR) != 0)
        return errno;

    if (close(ctx->sockets[p_ind].descriptor) != 0)
        return errno;

    rmc_reset_socket(&ctx->sockets[p_ind], p_ind);

    if (ctx->poll_remove)
        (*ctx->poll_remove)(&ctx->sockets[p_ind].poll_info, ctx->user_data);

    if (p_ind == ctx->max_socket_ind)
        _reset_max_socket_ind(ctx);
    
}


int rmc_get_poll_size(rmc_context_t* ctx, int *result)
{
    if (!ctx || !result)
        return EINVAL;

    *result = ctx->socket_count;

    return 0;
}


int rmc_get_poll_vector(rmc_context_t* ctx, rmc_poll_t* result, int* len)
{
    int ind = 0;
    int res_ind;
    int max_len = 0;

    if (!ctx || !result || !len)
        return EINVAL;

    max_len = *len;

    while(ind < ctx->max_socket_ind && res_ind < max_len) {
        if (ctx->sockets[ind].descriptor != -1)
            result[res_ind++] = ctx->sockets[ind].poll_info;

        ind++;
    }

    *len = res_ind;
}
