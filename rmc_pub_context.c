// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)



#include "rmc_internal.h"
#include "rmc_log.h"
#include <string.h>
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <assert.h>
#include <signal.h>


// =============
// CONTEXT MANAGEMENT
// =============
int rmc_pub_init_context(rmc_pub_context_t** context_res,
                         // Used to avoid loopback dispatch of published packets
                         rmc_node_id_t node_id,
                         char* mcast_group_addr,
                         int multicast_port,
                         // Interface IP to bind mcast to. Default: "0.0.0.0" (IFADDR_ANY)
                         char* mcast_if_addr,

                         // IP address to listen to for incoming subscription
                         // connection from subscribers receiving multicast packets
                         // Default: "0.0.0.0" (IFADDR_ANY)
                         char* control_listen_if_addr,
                         int control_listen_port,

                         user_data_t user_data,

                         rmc_poll_add_cb_t poll_add,
                         rmc_poll_modify_cb_t poll_modify,
                         rmc_poll_remove_cb_t poll_remove,

                         uint32_t max_subscribers,

                         void (*payload_free)(void* payload,
                                              payload_len_t payload_len,
                                              user_data_t user_data))
{
    struct in_addr addr;
    unsigned int seed = rmc_usec_monotonic_timestamp() & 0xFFFFFFFF;
    rmc_pub_context_t* ctx = 0;
    uint8_t* conn_vec = 0;

    if (!context_res || !mcast_group_addr)
        return EINVAL;

    ctx = (rmc_pub_context_t*) malloc(sizeof(rmc_pub_context_t));
    if (!ctx) {
        RMC_LOG_FATAL("Could not allocate %d bytes", (int) sizeof(rmc_pub_context_t));
        exit(255);
    }
    *context_res = ctx;

    conn_vec = (uint8_t*) malloc(sizeof(rmc_connection_t) * max_subscribers);
    if (!conn_vec) {
        RMC_LOG_FATAL("Could not allocate %d bytes for connections", (int) sizeof(rmc_connection_t) * max_subscribers);
        exit(255);
    }

    signal(SIGPIPE, SIG_IGN);
    // We can throw away seed result since we will only call rand here.
    ctx->node_id = node_id?node_id:rand_r(&seed);
    ctx->user_data = user_data;

    rmc_conn_init_connection_vector(&ctx->conn_vec,
                                    conn_vec,
                                    max_subscribers,
                                    ctx->user_data,
                                    poll_add,
                                    poll_modify,
                                    poll_remove);

    if (!control_listen_if_addr)
        control_listen_if_addr = "0.0.0.0";

    if (!mcast_if_addr)
        mcast_if_addr = "0.0.0.0";

    if (!inet_aton(mcast_group_addr, &addr)) {
        RMC_LOG_WARNING("Could not resolve multicast address %s to IP address\n",
                mcast_group_addr);
        return EINVAL;
    }
    ctx->mcast_group_addr = ntohl(addr.s_addr);

    if (!inet_aton(control_listen_if_addr, &addr)) {
        RMC_LOG_WARNING("Could not resolve tcp listen address %s to IP address\n",
                control_listen_if_addr);
        return EINVAL;
    }
    ctx->control_listen_if_addr = ntohl(addr.s_addr);

    if (!inet_aton(mcast_if_addr, &addr)) {
        fprintf(stderr, "rmc_activate_context(multicast_interface_addr): Could not resolve %s to IP address\n",
                mcast_if_addr);
        return EINVAL;
    }
    ctx->mcast_if_addr = ntohl(addr.s_addr);

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

    ctx->subscriber_connect_cb = 0;
    ctx->subscriber_disconnect_cb = 0;

    ctx->subscriber_connect_cb = 0;

    ctx->announce_cb = 0;
    ctx->announce_send_interval = 0;
    ctx->announce_next_send_ts = 0;

    ctx->traffic_suspend_threshold = 0;
    ctx->traffic_resume_threshold = 0;
    ctx->traffic_suspended = 0;

    // outgoing_payload_free() will be called when
    // pub_acket_ack() is called, which happens when a
    // subscriber sends an ack back for the given pid.
    // When all subscribers have acknowledged,
    // payload_free() will be called is called to free the payload.
    pub_init_context(&ctx->pub_ctx);

    ctx->subscribers = malloc(sizeof(pub_subscriber_t) * max_subscribers);
    RMC_LOG_DEBUG("Publisher Context init. node_id[0x%X] mcast_group[%s:%d] mcast_if[%s] user_data[0x%X]",
                  ctx->node_id, mcast_group_addr, multicast_port,  mcast_if_addr, user_data.u32);
    return 0;
}


int rmc_pub_activate_context(rmc_pub_context_t* ctx)
{
    struct sockaddr_in sock_addr;
    struct in_addr in_addr;
    socklen_t sock_len = sizeof(struct sockaddr_in);
    int on_flag = 1;

    if (!ctx)
        return EINVAL;

    //
    // Setup udp send descriptor to be received by multicast members.
    //
    ctx->mcast_send_descriptor = socket (AF_INET, SOCK_DGRAM, 0);

    if (ctx->mcast_send_descriptor == -1) {
        RMC_LOG_WARNING("socket(multicast): %s", strerror(errno));
        goto error;
    }

    // Setup multicast group membership
    memset((void*) &in_addr, 0, sizeof(in_addr));

    in_addr.s_addr = htonl(ctx->mcast_if_addr);
    if (setsockopt(ctx->mcast_send_descriptor,
                   IPPROTO_IP, IP_MULTICAST_IF, &in_addr, sizeof(in_addr)) < 0) {
        perror("rmc_activate_context(multicast_recv): setsockopt(IP_MULTICAST_IF)");
        goto error;
    }

    RMC_LOG_INFO("Bound sender to %X", ctx->mcast_if_addr);

    // Setup TCP listen
    // Did we specify a local interface address to bind to?
    ctx->listen_descriptor = socket (AF_INET, SOCK_STREAM, 0);
    if (ctx->listen_descriptor == -1) {
        RMC_LOG_WARNING("rmc_init_pub_context(): socket(listen): %s", strerror(errno));
        goto error;
    }

    if (setsockopt(ctx->listen_descriptor, SOL_SOCKET,
                   SO_REUSEADDR, &on_flag, sizeof(on_flag)) < 0) {
        RMC_LOG_WARNING("rmc_init_pub_context(): setsockopt(REUSEADDR): %s", strerror(errno));
        goto error;
    }

    if (setsockopt(ctx->listen_descriptor, SOL_SOCKET,
                   SO_REUSEPORT, &on_flag, sizeof(on_flag)) < 0) {
        RMC_LOG_WARNING("rmc_init_pub_context(): setsockopt(SO_REUSEPORT): %s", strerror(errno));
        goto error;
    }


    // Bind to local endpoint.
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = htonl(ctx->control_listen_if_addr);
    sock_addr.sin_port = htons(ctx->control_listen_port);

    if (bind(ctx->listen_descriptor,
             (struct sockaddr *) &sock_addr, sizeof(sock_addr)) < 0) {
        RMC_LOG_WARNING("rmc_init_pub_context(): bind(): %s", strerror(errno));
        goto error;
    }

    if (listen(ctx->listen_descriptor, RMC_LISTEN_SOCKET_BACKLOG) != 0) {
        RMC_LOG_WARNING("rmc_init_pub_context(): listen(): %s", strerror(errno));
        goto error;
    }

    // If control_listen_port is 0, use getsockname() to grab the os-assigned ephereal port.
    if (!ctx->control_listen_port) {
        sock_len = sizeof(sock_addr);
        if (getsockname(ctx->listen_descriptor, (struct sockaddr*) &sock_addr, &sock_len)) {
            RMC_LOG_FATAL("getsockname(bind): %s", strerror(errno));
            goto error;
        }
        ctx->control_listen_port = ntohs(sock_addr.sin_port);
        RMC_LOG_INFO("Ephereal tcp port picked by OS to use as control port: %d", ctx->control_listen_port);
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
    rmc_index_t ind = 0;
    rmc_index_t max = 0;

    if (!ctx)
        return EINVAL;

    // Callback to remnove listen and multicast descriptor
    // from caller's poll vector.
    if (ctx->conn_vec.poll_remove) {
        (*ctx->conn_vec.poll_remove)(ctx->user_data,
                                     ctx->mcast_send_descriptor,
                                     RMC_MULTICAST_INDEX);

        (*ctx->conn_vec.poll_remove)(ctx->user_data,
                                     ctx->listen_descriptor,
                                     RMC_LISTEN_INDEX);
    }

    rmc_conn_get_max_index_in_use(&ctx->conn_vec, &max);

    if (max != -1) {
        for(ind = 0; ind <= max; ++ind) {
            rmc_connection_t* conn = rmc_conn_find_by_index(&ctx->conn_vec,
                                                            ind);
            // Don't opereate on closed connections.
            if (!conn)
                continue;

            rmc_pub_close_connection(ctx, ind);
        }
    }

    close(ctx->mcast_send_descriptor);
    close(ctx->listen_descriptor);

    ctx->mcast_send_descriptor = -1;
    ctx->listen_descriptor = -1;

    return 0;
}

int rmc_pub_delete_context(rmc_pub_context_t* ctx)
{

    if (!ctx)
        return EINVAL;
    rmc_pub_deactivate_context(ctx);

    free(ctx->conn_vec.connections);
    free(ctx);
    return 0;
}

int rmc_pub_set_announce_interval(rmc_pub_context_t* ctx, uint32_t send_interval_usec)
{
    if (!ctx)
        return EINVAL;

    // If not currently set, do setup a timestamp.
    // If we already have a send timestamp, let it run its course per the old
    // interval, and then use the new send inteval once it has expired.
    if (send_interval_usec && !ctx->announce_next_send_ts)
        ctx->announce_next_send_ts = rmc_usec_monotonic_timestamp() + send_interval_usec;

    ctx->announce_send_interval = send_interval_usec;

    // Wipe any pending announce we are waiting for.
    if (!send_interval_usec)
        ctx->announce_next_send_ts = 0;
    return 0;
}

// Setup IP_MULTICAST_TTL for publishing multicast.
// Can be called once the context is activated.
int rmc_pub_set_multicast_ttl(rmc_pub_context_t* ctx, int hops)
{
    if (ctx->mcast_send_descriptor == -1)
        return ENOTCONN;

    if (setsockopt(ctx->mcast_send_descriptor, IPPROTO_IP,
                   IP_MULTICAST_TTL, &hops, sizeof(hops)) < 0) {
        RMC_LOG_WARNING("rmc_pub_set_multicast_ttl(): setsockopt(IP_MULTICAST_TTL): %s", strerror(errno));
        return errno;
    }
    return 0;
}

int rmc_pub_set_announce_callback(rmc_pub_context_t* ctx,
                                         uint8_t (*announce_cb)(struct rmc_pub_context* ctx,
                                                                void* payload,
                                                                payload_len_t max_payload_len,
                                                                payload_len_t* result_payload_len))
{
    if (!ctx)
        return EINVAL;

    ctx->announce_cb = announce_cb;

    return 0;
}




int rmc_pub_set_subscriber_connect_callback(rmc_pub_context_t* ctx,
                                            uint8_t (*connect_cb)(struct rmc_pub_context* ctx,
                                                                  uint32_t remote_ip,
                                                                  uint16_t remote_port))
{
    if (!ctx)
        return EINVAL;

    ctx->subscriber_connect_cb = connect_cb;

    return 0;
}



int rmc_pub_set_subscriber_disconnect_callback(rmc_pub_context_t* ctx,
                                               void (*disconnect_cb)(struct rmc_pub_context* ctx,
                                                                     uint32_t remote_ip,
                                                                     uint16_t remote_port))
{
    if (!ctx)
        return EINVAL;

    ctx->subscriber_disconnect_cb = disconnect_cb;

    return 0;
}


int rmc_pub_set_control_message_callback(rmc_pub_context_t* ctx,
                                         void (*control_message_cb)(struct rmc_pub_context* ctx,
                                                                    uint32_t publisher_address,
                                                                    uint16_t publisher_port,
                                                                    rmc_node_id_t node_id,
                                                                    void* payload,
                                                                    payload_len_t payload_len))
{
    if (!ctx)
        return EINVAL;

    ctx->subscriber_control_message_cb = control_message_cb;

    return 0;
}


user_data_t rmc_pub_user_data(rmc_pub_context_t* ctx)
{
    if (!ctx)
        return (user_data_t) { .u64 = 0 };

    return ctx->user_data;
}

rmc_node_id_t rmc_pub_node_id(rmc_pub_context_t* ctx)
{
    if (!ctx)
        return 0;

    return ctx->node_id;
}

int rmc_pub_set_user_data(rmc_pub_context_t* ctx, user_data_t user_data)
{
    if (!ctx)
        return EINVAL;

    ctx->user_data = user_data;
    return 0;
}

rmc_index_t rmc_pub_get_max_subscriber_count(rmc_pub_context_t* ctx)
{
    rmc_index_t res = 0;

    if (!ctx)
        return 0;

    rmc_conn_get_vector_size(&ctx->conn_vec, &res);
    return res;
}

uint32_t rmc_pub_get_subscriber_count(rmc_pub_context_t* ctx)
{
    rmc_index_t res = 0;

    if (!ctx)
        return 0;

    rmc_conn_get_active_connection_count(&ctx->conn_vec, &res);
    return res;
}

uint32_t rmc_pub_get_socket_count(rmc_pub_context_t* ctx)
{

    if (!ctx)
        return 0;

    return rmc_pub_get_subscriber_count(ctx) +
        (ctx->mcast_send_descriptor != -1)?1:0 +
        (ctx->listen_descriptor != -1 )?1:0;
}

int rmc_pub_throttling(rmc_pub_context_t* ctx,
                       uint32_t suspend_threshold,
                       uint32_t resume_threshold)
{
    if (!ctx)
        return EINVAL;

    if (suspend_threshold < resume_threshold) {
        RMC_LOG_WARNING("Traffic throttling suspend threhold[%d] is less than the restart value[%d]. Ignored.",
                        suspend_threshold, resume_threshold);

        return EINVAL;
    }
    ctx->traffic_suspend_threshold = suspend_threshold;
    ctx->traffic_resume_threshold = resume_threshold;
    return 0;
}
