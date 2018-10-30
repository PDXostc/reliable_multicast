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


static void _reset_socket(rmc_socket_t* sock, int index)
{
    sock->poll_info.action = 0;
    sock->poll_info.rmc_index = index;
    sock->descriptor = -1;
    sock->mode = RMC_SOCKET_MODE_UNUSED;
    circ_buf_init(&sock->read_buf, sock->read_buf_data, sizeof(sock->read_buf_data));
    circ_buf_init(&sock->write_buf, sock->write_buf_data, sizeof(sock->write_buf_data));
    memset(&sock->remote_address, 0, sizeof(sock->remote_address));
}





// =============
// CONTEXT MANAGEMENT
// =============
int rmc_init_context(rmc_context_t* ctx,
                     char* multicast_addr,
                     char* listen_ip,
                     int port,
                     void* (*payload_alloc)(payload_len_t),
                     void (*payload_free)(void*, payload_len_t),
                     void (*poll_add)(rmc_poll_t* poll),
                     void (*poll_modify)(rmc_poll_t* old_poll, rmc_poll_t* new_poll), 
                     void (*poll_remove)(rmc_poll_t* poll)) {

    int i = sizeof(ctx->sockets) / sizeof(ctx->sockets[0]);

    assert(ctx);

    while(i--) 
        _reset_socket(&ctx->sockets[i], i);
    

    strncpy(ctx->multicast_addr, multicast_addr, sizeof(ctx->multicast_addr));
    ctx->multicast_addr[sizeof(ctx->multicast_addr)-1] = 0;

    if (listen_ip) {
        strncpy(ctx->listen_ip, listen_ip, sizeof(ctx->listen_ip));
        ctx->listen_ip[sizeof(ctx->listen_ip)-1] = 0;
    } else
        ctx->listen_ip[0] = 0;

    ctx->port = port;
    ctx->poll_add = poll_add;
    ctx->poll_remove = poll_remove;
    ctx->payload_alloc = payload_alloc;
    ctx->payload_free = payload_free;
    ctx->socket_count = 0;
    ctx->max_socket_ind = -1;
    ctx->resend_timeout = RMC_RESEND_TIMEOUT_DEFAULT;

    // outgoing_payload_free() will be called when
    // pub_acket_ack() is called, which happens when a
    // subscriber sends an ack back for the given pid.
    // When all subscribers have acknowledged,
    // outgoing_payload_free() is called to free the payload.
    pub_init_context(&ctx->pub_ctx, payload_free);
    sub_init_context(&ctx->sub_ctx, 0);

    return 0;
}


int rmc_activate_context(rmc_context_t* ctx)
{
    struct sockaddr_in sock_addr;
    struct ip_mreq mreq;
    int flag = 1;

    if (!ctx)
        return EINVAL;


    if (ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].descriptor != -1)
        return EEXIST;

    ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].descriptor = socket (AF_INET, SOCK_DGRAM, 0);

    if (ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].descriptor == -1) {
        perror("rmc_listen(): socket(multicast)");
        goto error;
    }

    if (setsockopt(ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].descriptor, SOL_SOCKET,
                   SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
        perror("rmc_listen(): setsockopt(REUSEADDR)");
        goto error;
    }

    if (setsockopt(ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].descriptor, SOL_SOCKET,
                   SO_REUSEPORT, &flag, sizeof(flag)) < 0) {
        perror("rmc_listen(): setsockopt(SO_REUSEPORT)");
        goto error;
    }

    // Join multicast group
    if (!inet_aton(ctx->multicast_addr, &mreq.imr_multiaddr))
        goto error;


    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    if (setsockopt(ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].descriptor,
                   IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("rmc_listen(): setsockopt(IP_ADD_MEMBERSHIP)");
        goto error;
    }

    // Bind to local endpoint.
//    sock_addr.sin_family = AF_INET;
//    sock_addr.sin_addr.s_addr = htonl(INADDR_ANY);
//    sock_addr.sin_port = htons(INPORT_ANY);

//    if (bind(ctx->sockets[RMC_MULTICAST_SOCKET_INDEX],
//             (struct sockaddr *) &sock_addr, sizeof(sock_addr)) < 0) {
//        perror("rmc_listen(): bind()");
//        return errno;
//    }

    // setup remote endpoint
    memset((void*) &ctx->mcast_dest_addr, 0, sizeof(ctx->mcast_dest_addr));
    ctx->mcast_dest_addr.sin_family = AF_INET;
    ctx->mcast_dest_addr.sin_addr = mreq.imr_multiaddr;
    ctx->mcast_dest_addr.sin_port = htons(ctx->port);

    // Setup TCP listen
    // Did we specify a local interface address to bind to?
    ctx->sockets[RMC_LISTEN_SOCKET_INDEX].descriptor = socket (AF_INET, SOCK_STREAM, 0);
    if (ctx->sockets[RMC_LISTEN_SOCKET_INDEX].descriptor == -1) {
        perror("rmc_listen(): socket(listen)");
        goto error;
    }

    if (ctx->listen_ip[0] &&
        inet_aton(ctx->listen_ip, &sock_addr.sin_addr) != 1) {
        errno = EFAULT;
        goto error;
    }
    else
        sock_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    sock_addr.sin_port = htons(ctx->port);
    if (bind(ctx->sockets[RMC_LISTEN_SOCKET_INDEX].descriptor,
             (struct sockaddr *) &sock_addr, sizeof(sock_addr)) < 0) {
        perror("rmc_listen(): bind()");
        goto error;
    }

    if (listen(ctx->sockets[RMC_LISTEN_SOCKET_INDEX].descriptor, RMC_LISTEN_SOCKET_BACKLOG) != 0) {
        perror("rmc_listen(): listen()");
        goto error;
    }

    ctx->socket_count += 2;

    if (ctx->max_socket_ind < RMC_LISTEN_SOCKET_INDEX)
        ctx->max_socket_ind = RMC_LISTEN_SOCKET_INDEX;

    if (ctx->max_socket_ind < RMC_MULTICAST_SOCKET_INDEX)
        ctx->max_socket_ind = RMC_MULTICAST_SOCKET_INDEX;

    ctx->sockets[RMC_LISTEN_SOCKET_INDEX].poll_info.action = RMC_POLLREAD;
    ctx->sockets[RMC_LISTEN_SOCKET_INDEX].mode = RMC_SOCKET_MODE_OTHER;

    ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].poll_info.action = RMC_POLLREAD;
    ctx->sockets[RMC_LISTEN_SOCKET_INDEX].mode = RMC_SOCKET_MODE_OTHER;
    

    if (ctx->poll_add) {
        (*ctx->poll_add)(&ctx->sockets[RMC_LISTEN_SOCKET_INDEX].poll_info);
        (*ctx->poll_add)(&ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].poll_info);
    }

    return 0;

error:
    if (ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].descriptor != -1) {
        close(ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].descriptor);
        _reset_socket(&ctx->sockets[RMC_MULTICAST_SOCKET_INDEX], RMC_MULTICAST_SOCKET_INDEX);
    }

    if (ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].descriptor != -1) {
        close(ctx->sockets[RMC_LISTEN_SOCKET_INDEX].descriptor);
        _reset_socket(&ctx->sockets[RMC_LISTEN_SOCKET_INDEX], RMC_MULTICAST_SOCKET_INDEX);
    }

    return errno;
}

int rmc_deactivate_context(rmc_context_t* ctx)
{
    return 0;
}



