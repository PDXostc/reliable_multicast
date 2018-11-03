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
    sock->poll_info.descriptor = -1;
    sock->mode = RMC_SOCKET_MODE_UNUSED;
    circ_buf_init(&sock->read_buf, sock->read_buf_data, sizeof(sock->read_buf_data));
    circ_buf_init(&sock->write_buf, sock->write_buf_data, sizeof(sock->write_buf_data));
    memset(&sock->remote_address, 0, sizeof(sock->remote_address));
}

// Intermediate free function invoked by sub.c
static inline void _payload_free(void* payload, payload_len_t len, user_data_t user_data)
{
    rmc_context_t* ctx = (rmc_context_t*) user_data.ptr;

    if (*ctx->payload_free)
        (*ctx->payload_free)(ctx, payload, len);
    else
        free(payload);
}

// =============
// CONTEXT MANAGEMENT
// =============
int rmc_init_context(rmc_context_t* ctx,
                     char* multicast_addr,
                     char* listen_ip,
                     int port,
                     user_data_t user_data,
                     void (*poll_add)(rmc_context_t* context, rmc_poll_t* poll),
                     void (*poll_modify)(rmc_context_t* context,
                                         rmc_poll_t* old_poll,
                                         rmc_poll_t* new_poll),

                     void (*poll_remove)(rmc_context_t* context, rmc_poll_t* poll),
                     void* (*payload_alloc)(rmc_context_t* context, payload_len_t payload_len),
                     void (*payload_free)(rmc_context_t* context, void* payload, payload_len_t payload_len)) {

    
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

    ctx->mcast_descriptor = -1;
    ctx->listen_descriptor = -1;
    ctx->mcast_pinfo.rmc_index = RMC_MULTICAST_INDEX;
    ctx->mcast_pinfo.action = 0;
    ctx->mcast_pinfo.descriptor = -1;
    ctx->listen_pinfo.rmc_index = RMC_LISTEN_INDEX;
    ctx->listen_pinfo.action = 0;
    ctx->mcast_pinfo.descriptor = -1;

    ctx->port = port;
    ctx->user_data = user_data;
    ctx->poll_add = poll_add;
    ctx->poll_modify = poll_modify;
    ctx->poll_remove = poll_remove;
    ctx->payload_alloc = payload_alloc;
    ctx->payload_free = payload_free;
    ctx->socket_count = 0;
    ctx->max_socket_ind = -1; // No sockets in use
    ctx->resend_timeout = RMC_RESEND_TIMEOUT_DEFAULT;

    // outgoing_payload_free() will be called when
    // pub_acket_ack() is called, which happens when a
    // subscriber sends an ack back for the given pid.
    // When all subscribers have acknowledged,
    // outgoing_payload_free() is called to free the payload.
    pub_init_context(&ctx->pub_ctx,
                     (user_data_t) { .ptr = ctx },
                     _payload_free);
    sub_init_context(&ctx->sub_ctx, 0);

    return 0;
}


int rmc_activate_context(rmc_context_t* ctx)
{
    struct sockaddr_in sock_addr;
    struct ip_mreq mreq;
    int on_flag = 1;
    int off_flag = 0;

    if (!ctx)
        return EINVAL;

    if (ctx->mcast_descriptor != -1)
        return EEXIST;

    ctx->mcast_descriptor = socket (AF_INET, SOCK_DGRAM, 0);

    if (ctx->mcast_descriptor == -1) {
        perror("rmc_activate_context(): socket(multicast)");
        goto error;
    }

    if (setsockopt(ctx->mcast_descriptor, SOL_SOCKET,
                   SO_REUSEADDR, &on_flag, sizeof(on_flag)) < 0) {
        perror("rmc_activate_context(): setsockopt(REUSEADDR)");
        goto error;
    }

    if (setsockopt(ctx->mcast_descriptor, SOL_SOCKET,
                   SO_REUSEPORT, &on_flag, sizeof(on_flag)) < 0) {
        perror("rmc_activate_context(): setsockopt(SO_REUSEPORT)");
        goto error;
    }



    
    // Join multicast group
    if (!inet_aton(ctx->multicast_addr, &mreq.imr_multiaddr))
        goto error;


    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    if (setsockopt(ctx->mcast_descriptor,
                   IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("rmc_activate_context(): setsockopt(IP_ADD_MEMBERSHIP)");
        goto error;
    }

    memset((void*) &ctx->mcast_local_addr, 0, sizeof(ctx->mcast_local_addr));
    ctx->mcast_local_addr.sin_family = AF_INET;
    ctx->mcast_local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    ctx->mcast_local_addr.sin_port = htons(ctx->port);
    if (bind(ctx->mcast_descriptor,
             (struct sockaddr *) &ctx->mcast_local_addr,
             sizeof(ctx->mcast_local_addr)) < 0) {
        perror("rmc_listen(): bind()");
        return errno;
    }

    // setup remote endpoint
    memset((void*) &ctx->mcast_dest_addr, 0, sizeof(ctx->mcast_dest_addr));
    ctx->mcast_dest_addr.sin_family = AF_INET;
    ctx->mcast_dest_addr.sin_addr = mreq.imr_multiaddr;
    ctx->mcast_dest_addr.sin_port = htons(ctx->port);

    // FIXME: We need IP_MULTICAST_LOOP if other processes on the same
    //        host are to receive sent packets. We need to figure out
    //        a wayu to transmit mcast data between two processes on
    //        the same host without having to use IP_MULTICAST_LOOP
    //        since its presence will trigger a spurious mcast read
    //        for every send that a process does.
    //        See _process_multicast_read() which now checks for and
    //        discards loopback data.
    //
    if (setsockopt(ctx->mcast_descriptor,
                   IPPROTO_IP, IP_MULTICAST_LOOP, &on_flag, sizeof(on_flag)) < 0) {
        perror("rmc_activate_context(): setsockopt(IP_MULTICAST_LOOP)");
        goto error;
    }

    // 
    // Setup TCP listen
    // Did we specify a local interface address to bind to?
    ctx->listen_descriptor = socket (AF_INET, SOCK_STREAM, 0);
    if (ctx->listen_descriptor == -1) {
        perror("rmc_activate_context(): socket(listen)");
        goto error;
    }

    if (setsockopt(ctx->listen_descriptor, SOL_SOCKET,
                   SO_REUSEADDR, &on_flag, sizeof(on_flag)) < 0) {
        perror("rmc_activate_context(): setsockopt(REUSEADDR)");
        goto error;
    }

    if (setsockopt(ctx->listen_descriptor, SOL_SOCKET,
                   SO_REUSEPORT, &on_flag, sizeof(on_flag)) < 0) {
        perror("rmc_activate_context(): setsockopt(SO_REUSEPORT)");
        goto error;
    }


    // Bind to local endpoint.
    sock_addr.sin_family = AF_INET;

    if (ctx->listen_ip[0] &&
        inet_aton(ctx->listen_ip, &sock_addr.sin_addr) != 1) {
        errno = EFAULT;
        goto error;
    }
    else
        sock_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    sock_addr.sin_port = htons(ctx->port);
    if (bind(ctx->listen_descriptor,
             (struct sockaddr *) &sock_addr, sizeof(sock_addr)) < 0) {
        perror("rmc_activate_context(): bind()");
        goto error;
    }

    if (listen(ctx->listen_descriptor, RMC_LISTEN_SOCKET_BACKLOG) != 0) {
        perror("rmc_activate_context(): listen()");
        goto error;
    }

    ctx->socket_count += 2;

    ctx->mcast_pinfo.action = RMC_POLLREAD;
    ctx->mcast_pinfo.descriptor = ctx->mcast_descriptor;
    ctx->listen_pinfo.action = RMC_POLLREAD;
    ctx->listen_pinfo.descriptor = ctx->listen_descriptor;

    if (ctx->poll_add) {
        (*ctx->poll_add)(ctx, &ctx->mcast_pinfo);
        (*ctx->poll_add)(ctx, &ctx->listen_pinfo);
    }

    return 0;

error:
    if (ctx->mcast_descriptor != -1) {
        close(ctx->mcast_descriptor);
        ctx->mcast_descriptor = -1;
        ctx->mcast_pinfo.descriptor = -1;
    }
    

    if (ctx->listen_descriptor != -1) {
        close(ctx->listen_descriptor);
        ctx->listen_descriptor = -1;
        ctx->listen_pinfo.descriptor = -1;
    }

    return errno;
}

int rmc_deactivate_context(rmc_context_t* ctx)
{
    return 0;
}


user_data_t rmc_user_data(rmc_context_t* ctx)
{
    if (!ctx)
        return (user_data_t) { .u64 = 0 };

    return ctx->user_data;
}

int rmc_set_user_data(rmc_context_t* ctx, user_data_t user_data)
{
    if (!ctx)
        return EINVAL;

    ctx->user_data = user_data;
    return 0;
}
