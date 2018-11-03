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
                     // Interface IP to bind mcast to. Default: "0.0.0.0" (IFADDR_ANY)
                     char* multicast_iface_addr, 

                     // IP address to listen to for incoming subscription
                     // connection from subscribers receiving multicast packets
                     // Default: "0.0.0.0" (IFADDR_ANY)
                     char* listen_iface_addr, 
                     int port,
                     user_data_t user_data,
                     void (*poll_add)(rmc_context_t* context, rmc_poll_t* poll),
                     void (*poll_modify)(rmc_context_t* context,
                                         rmc_poll_t* old_poll,
                                         rmc_poll_t* new_poll),

                     void (*poll_remove)(rmc_context_t* context, rmc_poll_t* poll),
                     void* (*payload_alloc)(rmc_context_t* context, payload_len_t payload_len),
                     void (*payload_free)(rmc_context_t* context, void* payload, payload_len_t payload_len)) {

    
    int ind = 0;

    if (!ctx || !multicast_addr)
        return EINVAL;

    ind = sizeof(ctx->sockets) / sizeof(ctx->sockets[0]);
    while(ind--) 
        _reset_socket(&ctx->sockets[ind], ind);
    
    if (!multicast_iface_addr)
        multicast_iface_addr = "0.0.0.0";

    if (!listen_iface_addr)
        listen_iface_addr = "0.0.0.0";

    strncpy(ctx->multicast_addr, multicast_addr, sizeof(ctx->multicast_addr));
    ctx->multicast_addr[sizeof(ctx->multicast_addr)-1] = 0;

    strncpy(ctx->multicast_iface_addr, multicast_iface_addr, sizeof(ctx->multicast_iface_addr));
    ctx->multicast_iface_addr[sizeof(ctx->multicast_iface_addr)-1] = 0;
    

    strncpy(ctx->listen_iface_addr, listen_iface_addr, sizeof(ctx->listen_iface_addr));
    ctx->listen_iface_addr[sizeof(ctx->listen_iface_addr)-1] = 0;

    ctx->mcast_send_descriptor = -1;
    ctx->mcast_recv_descriptor = -1;
    ctx->listen_descriptor = -1;

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
    srand(rmc_usec_monotonic_timestamp() & 0xFFFFFFFF);
    ctx->context_id = rand();
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
    socklen_t sock_len = sizeof(struct sockaddr_in);
    struct ip_mreq mreq;
    int on_flag = 1;
    int off_flag = 0;

    if (!ctx)
        return EINVAL;

    if (ctx->mcast_recv_descriptor != -1)
        return EEXIST;

    //
    // Setup the multicast receiver socket.
    //
    ctx->mcast_recv_descriptor = socket (AF_INET, SOCK_DGRAM, 0);

    if (ctx->mcast_recv_descriptor == -1) {
        perror("rmc_activate_context(multicast_recv): socket()");
        goto error;
    }

    if (setsockopt(ctx->mcast_recv_descriptor, SOL_SOCKET,
                   SO_REUSEPORT, &on_flag, sizeof(on_flag)) < 0) {
        perror("rmc_activate_context(multicast_recv): setsockopt(SO_REUSEPORT)");
        goto error;
    }

    memset((void*) &sock_addr, 0, sizeof(sock_addr));

    sock_addr.sin_family = AF_INET;
    if (!inet_aton(ctx->multicast_iface_addr, &sock_addr.sin_addr)) {
        fprintf(stderr, "rmc_activate_context(multicast_interface_addr): Could not resolve %s to IP address\n",
                ctx->multicast_addr);
        goto error;
    }


    sock_addr.sin_port = htons(ctx->port);

    if (bind(ctx->mcast_recv_descriptor,
             (struct sockaddr *) &sock_addr,
             sizeof(sock_addr)) < 0) {
        perror("rmc_listen(multicast_recv): bind()");
        return errno;
    }


    // Join multicast group
    if (!inet_aton(ctx->multicast_addr, &mreq.imr_multiaddr)) {
        fprintf(stderr, "rmc_activate_context(multicast_addr): Could not resolve %s to IP address\n",
                ctx->multicast_addr);
        goto error;
    }

    memcpy(&mreq.imr_interface, &sock_addr.sin_addr, sizeof(sock_addr.sin_addr));

    if (setsockopt(ctx->mcast_recv_descriptor,
                   IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("rmc_activate_context(multicast_recv): setsockopt(IP_ADD_MEMBERSHIP)");
        goto error;
    }

    // FIXME: We need IP_MULTICAST_LOOP if other processes on the same
    //        host are to receive sent packets. We need to figure out
    //        a wayu to transmit mcast data between two processes on
    //        the same host without having to use IP_MULTICAST_LOOP
    //        since its presence will trigger a spurious mcast read
    //        for every send that a process does.
    //        See _process_multicast_read() which now checks for and
    //        discards loopback data.
    //
    if (setsockopt(ctx->mcast_recv_descriptor,
                   IPPROTO_IP, IP_MULTICAST_LOOP, &on_flag, sizeof(on_flag)) < 0) {
        perror("rmc_activate_context(): setsockopt(IP_MULTICAST_LOOP)");
        goto error;
    }

    //
    // Setup udp send edscriptor to be received by multicast members.
    //
    ctx->mcast_send_descriptor = socket (AF_INET, SOCK_DGRAM, 0);

    if (ctx->mcast_send_descriptor == -1) {
        perror("rmc_activate_context(): socket(multicast)");
        goto error;
    }


    // setup destination address to be used by _process_multicast_write
    memset((void*) &ctx->mcast_dest_addr, 0, sizeof(ctx->mcast_dest_addr));
    ctx->mcast_dest_addr.sin_family = AF_INET;
    ctx->mcast_dest_addr.sin_addr = mreq.imr_multiaddr;
    ctx->mcast_dest_addr.sin_port = htons(ctx->port);

    memset((void*) &ctx->mcast_local_addr, 0, sizeof(ctx->mcast_local_addr));
    getsockname(ctx->mcast_send_descriptor, &ctx->mcast_local_addr, &sock_len);

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

    if (inet_aton(ctx->listen_iface_addr, &sock_addr.sin_addr) != 1) {
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


    if (ctx->poll_add) {
        rmc_poll_t pinfo;

        pinfo.descriptor = ctx->mcast_send_descriptor;
        pinfo.action = 0;
        pinfo.rmc_index = RMC_MULTICAST_SEND_INDEX;
        (*ctx->poll_add)(ctx, &pinfo);

        pinfo.descriptor = ctx->mcast_recv_descriptor;
        pinfo.action = RMC_POLLREAD;
        pinfo.rmc_index = RMC_MULTICAST_RECV_INDEX;
        (*ctx->poll_add)(ctx, &pinfo);

        pinfo.descriptor = ctx->listen_descriptor;
        pinfo.action = RMC_POLLREAD;
        pinfo.rmc_index = RMC_LISTEN_INDEX;
        (*ctx->poll_add)(ctx, &pinfo);
    }

    return 0;

error:
    if (ctx->mcast_recv_descriptor != -1) {
        close(ctx->mcast_recv_descriptor);
        ctx->mcast_recv_descriptor = -1;
    }
    
    if (ctx->mcast_send_descriptor != -1) {
        close(ctx->mcast_send_descriptor);
        ctx->mcast_send_descriptor = -1;
    }

    if (ctx->listen_descriptor != -1) {
        close(ctx->listen_descriptor);
        ctx->listen_descriptor = -1;
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
