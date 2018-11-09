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

static void _reset_connection(rmc_context_t* ctx, int index)
{
    rmc_connection_t* sock = &ctx->connections[index];

    sock->action = 0;
    sock->rmc_index = index;
    sock->descriptor = -1;
    sock->owner = ctx;
    sock->mode = RMC_CONNECTION_MODE_UNUSED;
    circ_buf_init(&sock->read_buf, sock->read_buf_data, sizeof(sock->read_buf_data));
    circ_buf_init(&sock->write_buf, sock->write_buf_data, sizeof(sock->write_buf_data));
    memset(&sock->remote_address, 0, sizeof(sock->remote_address));
}

// =============
// CONTEXT MANAGEMENT
// =============
int rmc_init_context(rmc_context_t* ctx,
                     char* mcast_group_addr,
                     // Interface IP to bind mcast to. Default: "0.0.0.0" (IFADDR_ANY)
                     char* mcast_if_addr, 

                     // IP address to listen to for incoming subscription
                     // connection from subscribers receiving multicast packets
                     // Default: "0.0.0.0" (IFADDR_ANY)
                     char* listen_if_addr, 
                     int multicast_port,
                     int listen_port,
                     user_data_t user_data,

                     void (*poll_add)(struct rmc_context* context,
                                      int descriptor,
                                      rmc_connection_index_t index,
                                      rmc_poll_action_t initial_action),

                     void (*poll_modify)(struct rmc_context* context,
                                         int descriptor,
                                         rmc_connection_index_t index,
                                         rmc_poll_action_t old_action,
                                         rmc_poll_action_t new_action),

                     void (*poll_remove)(struct rmc_context* context,
                                         int descriptor,
                                         rmc_connection_index_t index),
                     void* (*sub_payload_alloc)(payload_len_t payload_len,
                                                user_data_t user_data),

                     void (*pub_payload_free)(void* payload,
                                              payload_len_t payload_len,
                                              user_data_t user_data))
{
    int ind = 0;
    struct in_addr addr;
                                     
    if (!ctx || !mcast_group_addr)
        return EINVAL;

    ind = sizeof(ctx->connections) / sizeof(ctx->connections[0]);
    while(ind--) 
        _reset_connection(ctx, ind);
    
    if (!mcast_if_addr)
        mcast_if_addr = "0.0.0.0";

    if (!listen_if_addr)
        listen_if_addr = "0.0.0.0";

    if (!inet_aton(mcast_group_addr, &addr)) {
        fprintf(stderr, "rmc_activate_context(multicast_group_addr): Could not resolve %s to IP address\n",
                mcast_group_addr);
        return EINVAL;
    }
    ctx->mcast_group_addr = ntohl(addr.s_addr);

    if (!inet_aton(mcast_if_addr, &addr)) {
        fprintf(stderr, "rmc_activate_context(multicast_interface_addr): Could not resolve %s to IP address\n",
                mcast_if_addr);
        return EINVAL;
    }
    ctx->mcast_if_addr = ntohl(addr.s_addr);
    
    if (!inet_aton(listen_if_addr, &addr)) {
        fprintf(stderr, "rmc_activate_context(_interface_addr): Could not resolve %s to IP address\n",
                listen_if_addr);
        return EINVAL;
    }
    ctx->listen_if_addr = ntohl(addr.s_addr);

    ctx->mcast_port = multicast_port;
    ctx->listen_port = listen_port;

    ctx->mcast_send_descriptor = -1;
    ctx->mcast_recv_descriptor = -1;
    ctx->listen_descriptor = -1;

    ctx->user_data = user_data;
    ctx->poll_add = poll_add;
    ctx->poll_modify = poll_modify;
    ctx->poll_remove = poll_remove;

    ctx->sub_payload_alloc = sub_payload_alloc;
    ctx->pub_payload_free = pub_payload_free;

    ctx->connection_count = 0;
    ctx->resend_timeout = RMC_DEFAULT_PACKET_TIMEOUT;
    ctx->max_connection_ind = -1; // No connections in use
    srand(rmc_usec_monotonic_timestamp() & 0xFFFFFFFF);
    ctx->context_id = rand();
    // outgoing_payload_free() will be called when
    // pub_acket_ack() is called, which happens when a
    // subscriber sends an ack back for the given pid.
    // When all subscribers have acknowledged,
    // outgoing_payload_free() is called to free the payload.
    pub_init_context(&ctx->pub_ctx);

    sub_init_context(&ctx->sub_ctx);

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
    sock_addr.sin_addr.s_addr = htonl(ctx->mcast_if_addr);
    sock_addr.sin_port = htons(ctx->mcast_port);

    if (bind(ctx->mcast_recv_descriptor,
             (struct sockaddr *) &sock_addr,
             sizeof(sock_addr)) < 0) {
        perror("rmc_listen(multicast_recv): bind()");
        return errno;
    }


    // Setup multicast group membership
    mreq.imr_multiaddr.s_addr = htonl(ctx->mcast_group_addr);
    mreq.imr_interface.s_addr = htonl(ctx->mcast_if_addr);

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
    // Setup udp send descriptor to be received by multicast members.
    //
    ctx->mcast_send_descriptor = socket (AF_INET, SOCK_DGRAM, 0);

    if (ctx->mcast_send_descriptor == -1) {
        perror("rmc_activate_context(): socket(multicast)");
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
    sock_addr.sin_addr.s_addr = htonl(ctx->listen_if_addr);
    sock_addr.sin_port = htons(ctx->listen_port);

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
        (*ctx->poll_add)(ctx,
                         ctx->mcast_send_descriptor,
                         RMC_MULTICAST_SEND_INDEX,
                         0);

        (*ctx->poll_add)(ctx,
                         ctx->mcast_recv_descriptor,
                         RMC_MULTICAST_RECV_INDEX,
                         RMC_POLLREAD);

        (*ctx->poll_add)(ctx,
                         ctx->listen_descriptor,
                         RMC_LISTEN_INDEX,
                         RMC_POLLREAD);
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

rmc_context_id_t rmc_context_id(rmc_context_t* ctx)
{
    if (!ctx)
        return 0;

    return ctx->context_id;
}

int rmc_set_user_data(rmc_context_t* ctx, user_data_t user_data)
{
    if (!ctx)
        return EINVAL;

    ctx->user_data = user_data;
    return 0;
}
