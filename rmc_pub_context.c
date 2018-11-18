// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)



#define _GNU_SOURCE
#include "reliable_multicast.h"
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
// CONTEXT MANAGEMENT
// =============
int rmc_pub_init_context(rmc_pub_context_t* ctx,
                         // Used to avoid loopback dispatch of published packets
                         rmc_context_id_t context_id,
                         char* mcast_group_addr,
                         int multicast_port,

                         // IP address to listen to for incoming subscription
                         // connection from subscribers receiving multicast packets
                         // Default: "0.0.0.0" (IFADDR_ANY)
                         char* control_listen_if_addr, 
                         int control_listen_port,

                         user_data_t user_data,

                         rmc_poll_add_cb_t poll_add,
                         rmc_poll_modify_cb_t poll_modify,
                         rmc_poll_remove_cb_t poll_remove,

                         uint8_t* conn_vec,
                         uint32_t conn_vec_size, // In bytes.

                         void (*payload_free)(void* payload,
                                              payload_len_t payload_len,
                                              user_data_t user_data))
{
    int ind = 0;
    struct in_addr addr;
    int seed = rmc_usec_monotonic_timestamp() & 0xFFFFFFFF;

    if (!ctx || !mcast_group_addr)
        return EINVAL;

    // We can throw away seed result since we will only call rand here.
    ctx->context_id = context_id?context_id:rand_r(&seed);
    ctx->user_data = user_data;

    _rmc_conn_init_connection_vector(&ctx->conn_vec,
                                     conn_vec,
                                     conn_vec_size,
                                     ctx->user_data,
                                     poll_add,
                                     poll_modify,
                                     poll_remove);
    
    

    if (!control_listen_if_addr)
        control_listen_if_addr = "0.0.0.0";

    if (!inet_aton(mcast_group_addr, &addr)) {
        fprintf(stderr, "rmc_init_pub_context(multicast_group_addr): Could not resolve %s to IP address\n",
                mcast_group_addr);
        return EINVAL;
    }
    ctx->mcast_group_addr = ntohl(addr.s_addr);

    ctx->mcast_port = multicast_port;
    ctx->control_listen_port = control_listen_port;

    ctx->mcast_send_descriptor = -1;
    ctx->listen_descriptor = -1;

    ctx->user_data = user_data;
    ctx->conn_vec.poll_add = poll_add;
    ctx->conn_vec.poll_modify = poll_modify;
    ctx->conn_vec.poll_remove = poll_remove;


    ctx->payload_free = payload_free;

    ctx->resend_timeout = RMC_DEFAULT_PACKET_TIMEOUT;

    // outgoing_payload_free() will be called when
    // pub_acket_ack() is called, which happens when a
    // subscriber sends an ack back for the given pid.
    // When all subscribers have acknowledged,
    // outgoing_payload_free() is called to free the payload.
    pub_init_context(&ctx->pub_ctx);

    ctx->subscribers = malloc(sizeof(pub_subscriber_t) * conn_vec_size);
    return 0;
}


int rmc_pub_activate_context(rmc_pub_context_t* ctx)
{
    struct sockaddr_in sock_addr;
    socklen_t sock_len = sizeof(struct sockaddr_in);
    struct ip_mreq mreq;
    int on_flag = 1;
    int off_flag = 0;

    if (!ctx)
        return EINVAL;

    //
    // Setup udp send descriptor to be received by multicast members.
    //
    ctx->mcast_send_descriptor = socket (AF_INET, SOCK_DGRAM, 0);

    if (ctx->mcast_send_descriptor == -1) {
        perror("rmc_init_pub_context(): socket(multicast)");
        goto error;
    }

    // Setup TCP listen
    // Did we specify a local interface address to bind to?
    ctx->listen_descriptor = socket (AF_INET, SOCK_STREAM, 0);
    if (ctx->listen_descriptor == -1) {
        perror("rmc_init_pub_context(): socket(listen)");
        goto error;
    }

    if (setsockopt(ctx->listen_descriptor, SOL_SOCKET,
                   SO_REUSEADDR, &on_flag, sizeof(on_flag)) < 0) {
        perror("rmc_init_pub_context(): setsockopt(REUSEADDR)");
        goto error;
    }

    if (setsockopt(ctx->listen_descriptor, SOL_SOCKET,
                   SO_REUSEPORT, &on_flag, sizeof(on_flag)) < 0) {
        perror("rmc_init_pub_context(): setsockopt(SO_REUSEPORT)");
        goto error;
    }


    // Bind to local endpoint.
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = htonl(ctx->control_listen_if_addr);
    sock_addr.sin_port = htons(ctx->control_listen_port);

    if (bind(ctx->listen_descriptor,
             (struct sockaddr *) &sock_addr, sizeof(sock_addr)) < 0) {
        perror("rmc_init_pub_context(): bind()");
        goto error;
    }

    if (listen(ctx->listen_descriptor, RMC_LISTEN_SOCKET_BACKLOG) != 0) {
        perror("rmc_init_pub_context(): listen()");
        goto error;
    }


    if (ctx->conn_vec.poll_add) {
        (*ctx->conn_vec.poll_add)(ctx->user_data,
                                  ctx->mcast_send_descriptor,
                                  RMC_MULTICAST_INDEX,
                                  RMC_POLLREAD);

        (*ctx->conn_vec.poll_add)(ctx->user_data,
                                  ctx->listen_descriptor,
                                  RMC_LISTEN_INDEX,
                                  RMC_POLLREAD);
    }

    return 0;

error:
    
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

int rmc_pub_deactivate_context(rmc_pub_context_t* ctx)
{
    return 0;
}

user_data_t rmc_pub_user_data(rmc_pub_context_t* ctx)
{
    if (!ctx)
        return (user_data_t) { .u64 = 0 };

    return ctx->user_data;
}

rmc_context_id_t rmc_pub_context_id(rmc_pub_context_t* ctx)
{
    if (!ctx)
        return 0;

    return ctx->context_id;
}

int rmc_pub_set_user_data(rmc_pub_context_t* ctx, user_data_t user_data)
{
    if (!ctx)
        return EINVAL;

    ctx->user_data = user_data;
    return 0;
}

