// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)



#define _GNU_SOURCE
#include "reliable_multicast.h"
#include "rmc_log.h"
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>

#include "rmc_list_template.h"
RMC_LIST_IMPL(rmc_index_list, rmc_index_node, rmc_index_t) 

// =============
// CONTEXT MANAGEMENT
// =============
int rmc_sub_init_context(rmc_sub_context_t* ctx,
                         // Used to avoid loopback dispatch of published packets
                         rmc_node_id_t node_id,
                         char* mcast_group_addr,
                         // Interface IP to bind mcast to. Default: "0.0.0.0" (IFADDR_ANY)
                         char* mcast_if_addr, 
                         int multicast_port,

                         user_data_t user_data,

                         rmc_poll_add_cb_t poll_add,
                         rmc_poll_modify_cb_t poll_modify,
                         rmc_poll_remove_cb_t poll_remove,
                         
                         uint8_t* conn_vec,
                         uint32_t conn_vec_size, // In bytes.

                         void* (*payload_alloc)(payload_len_t payload_len,
                                                user_data_t user_data),
                         void (*payload_free)(void* payload,
                                              payload_len_t payload_len,
                                              user_data_t user_data))
{
    int ind = 0;
    struct in_addr addr;
    int seed = rmc_usec_monotonic_timestamp() & 0xFFFFFFFF;
                                     
    if (!ctx || !mcast_group_addr)
        return EINVAL;

    sub_packet_list_init(&ctx->dispatch_ready, 0, 0, 0);
    rmc_index_list_init(&ctx->pub_ack_list, 0, 0, 0);

    signal(SIGPIPE, SIG_IGN);
    // We can throw away seed result since we will only call rand here.
    ctx->node_id = node_id?node_id:rand_r(&seed);
    ctx->user_data = user_data;
    ctx->announce_cb = 0;
    ctx->subscription_complete_cb = 0;
    ctx->packet_ready_cb = 0;
    rmc_conn_init_connection_vector(&ctx->conn_vec,
                                    conn_vec,
                                    conn_vec_size,
                                    ctx->user_data,
                                    poll_add,
                                    poll_modify,
                                    poll_remove);
    
    if (!mcast_if_addr)
        mcast_if_addr = "0.0.0.0";


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
    


    ctx->mcast_port = multicast_port;

    ctx->mcast_recv_descriptor = -1;


    ctx->conn_vec.poll_add = poll_add;
    ctx->conn_vec.poll_modify = poll_modify;
    ctx->conn_vec.poll_remove = poll_remove;

    ctx->payload_alloc = payload_alloc;
    ctx->payload_free = payload_free;

    ctx->ack_timeout = RMC_DEFAULT_ACK_TIMEOUT;


    // FIXME: Better memory management
    ctx->publishers = malloc(sizeof(sub_publisher_t) * conn_vec_size);

    RMC_LOG_DEBUG("Subscriber Context init. node_id[%u] mcast_group[%s:%d] user_data[%u]",
                  ctx->node_id, mcast_group_addr, multicast_port, user_data.u32);
    return 0;
}


int rmc_sub_activate_context(rmc_sub_context_t* ctx)
{
    struct sockaddr_in sock_addr;
    socklen_t sock_len = sizeof(struct sockaddr_in);
    struct ip_mreq mreq;
    int on_flag = 1;
    int off_flag = 0;
    int sz = 1024*1024;

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
        RMC_LOG_ERROR("setsockopt(SO_REUSEPORT)");
        goto error;
    }

    if (setsockopt(ctx->mcast_recv_descriptor, SOL_SOCKET,
                   SO_RCVBUF, &sz, sizeof(sz)) < 0) {
        RMC_LOG_ERROR("setsockopt(SO_RCVBUF)");
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

    if (ctx->conn_vec.poll_add) 
        (*ctx->conn_vec.poll_add)(ctx->user_data,
                                  ctx->mcast_recv_descriptor,
                                  RMC_MULTICAST_INDEX,
                                  RMC_POLLREAD);

    return 0;

error:
    if (ctx->mcast_recv_descriptor != -1) {
        close(ctx->mcast_recv_descriptor);
        ctx->mcast_recv_descriptor = -1;
    }
    

    return errno;
}



int rmc_sub_deactivate_context(rmc_sub_context_t* ctx)
{
    rmc_index_t ind = 0;
    rmc_index_t max = 0;
    sub_packet_t *pack;

    if (!ctx)
        return EINVAL;

    // Empty all packets that are dispatch ready.
    while(sub_packet_list_pop_head(&ctx->dispatch_ready, &pack)) 
        rmc_sub_packet_dispatched(ctx, pack);

    // Empty ack list
    rmc_index_list_empty(&ctx->pub_ack_list);

    close(ctx->mcast_recv_descriptor);
    if (ctx->conn_vec.poll_remove) 
        (*ctx->conn_vec.poll_remove)(ctx->user_data,
                                     ctx->mcast_recv_descriptor,
                                     RMC_MULTICAST_INDEX);

    ctx->mcast_recv_descriptor = -1;
    
    rmc_conn_get_max_index_in_use(&ctx->conn_vec, &max);
    for(ind = 0; ind <= max; ++ind) {
        rmc_connection_t* conn = rmc_conn_find_by_index(&ctx->conn_vec,
                                                        ind);
        // Don't opereate on closed connections.
        if (!conn) 
            continue;

        rmc_sub_close_connection(ctx, ind);
    }

    return 0;
}

int rmc_sub_set_announce_callback(rmc_sub_context_t* ctx,
                                  uint8_t (*announce_cb)(struct rmc_sub_context* ctx,
                                                         uint32_t listen_ip,
                                                         in_port_t listen_port,
                                                         rmc_node_id_t node_id,
                                                         void* payload,
                                                         payload_len_t payload_len))
{
    if (!ctx)
        return EINVAL;

    ctx->announce_cb = announce_cb;
    return 0;
}

int rmc_sub_set_subscription_complete_callback(rmc_sub_context_t* ctx,
                                               void (*subscription_complete_cb)
                                               (struct rmc_sub_context* ctx,
                                                uint32_t listen_ip,
                                                in_port_t listen_port,
                                                rmc_node_id_t node_id))
{
    if (!ctx)
        return EINVAL;

    ctx->subscription_complete_cb = subscription_complete_cb;
    return 0;
}

user_data_t rmc_sub_user_data(rmc_sub_context_t* ctx)
{
    if (!ctx)
        return (user_data_t) { .u64 = 0 };

    return ctx->user_data;
}

int rmc_sub_set_user_data(rmc_sub_context_t* ctx, user_data_t user_data)
{
    if (!ctx)
        return EINVAL;

    ctx->user_data = user_data;
    return 0;
}

rmc_node_id_t rmc_sub_node_id(rmc_sub_context_t* ctx)
{
    if (!ctx)
        return 0;

    return ctx->node_id;
}

rmc_index_t rmc_sub_get_max_publisher_count(rmc_sub_context_t* ctx)
{
    rmc_index_t res = 0;

    if (!ctx)
        return 0;

    rmc_conn_get_vector_size(&ctx->conn_vec, &res);
    return res;
}

rmc_index_t rmc_sub_get_publisher_count(rmc_sub_context_t* ctx)
{
    rmc_index_t res = 0;

    if (!ctx)
        return 0;
    
    rmc_conn_get_active_connection_count(&ctx->conn_vec, &res);
    return res;
}


int rmc_sub_set_packet_ready_callback(rmc_sub_context_t* ctx,
                                      void (*packet_ready_cb)(struct rmc_sub_context* ctx))
{
    if (!ctx)
        return EINVAL;

    ctx->packet_ready_cb = packet_ready_cb;
    return 0;
}

uint32_t rmc_sub_get_socket_count(rmc_sub_context_t* ctx)
{
    rmc_index_t res = 0;

    if (!ctx)
        return 0;
    
    return rmc_sub_get_publisher_count(ctx) +
        (ctx->mcast_recv_descriptor != -1)?1:0;
}

