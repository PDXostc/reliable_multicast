// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)



#define _GNU_SOURCE
#include "rmc_internal.h"
#include "rmc_log.h"
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

// =============
// TIMEOUT MANAGEMENT
// =============
static int process_sent_packet_timeout(rmc_pub_context_t* ctx,
                                       pub_subscriber_t* sub,
                                       pub_packet_t* pack)
{
    // Send the packet via TCP.
    rmc_connection_t* conn = 0;
    int res = 0;
    char group_addr[80];
    char remote_addr[80];

    if (!ctx || !sub || !pack)
        return EINVAL;

    conn = (rmc_connection_t*) pub_subscriber_user_data(sub).ptr;

    strcpy(group_addr, inet_ntoa( (struct in_addr) { .s_addr = htonl(ctx->mcast_group_addr) }));
    strcpy(remote_addr, inet_ntoa( (struct in_addr) { .s_addr = htonl(conn->remote_address) }));

    if (conn->mode != RMC_CONNECTION_MODE_CONNECTED) {
        RMC_LOG_INDEX_INFO(conn->connection_index,
                           "pid[%lu] mcast[%s:%d] listen[%s:%d] -> Disconnected. Dropped resend attempt",
                           pack->pid,
                           group_addr,
                           ctx->mcast_port,
                           remote_addr,
                           ctx->control_listen_port);

        rmc_pub_packet_ack(ctx, conn, pack->pid) ;
        return 0;

    }

    RMC_LOG_INDEX_COMMENT(conn->connection_index,
                          "Resending pid[%lu] len[%d] mcast[%s:%d] listen[%s:%d]",
                          pack->pid,
                          pack->payload_len,
                          group_addr,
                          ctx->mcast_port,
                          remote_addr,
                          ctx->control_listen_port);

    if (!conn || conn->mode != RMC_CONNECTION_MODE_CONNECTED)
        return EINVAL;

    res = rmc_pub_resend_packet(ctx, conn, pack);
    RMC_LOG_INDEX_DEBUG(conn->connection_index,
                        "rmc_pub_resend_packet: %d/%s", res, strerror(res));

    // Internal ack of the packet since we now can do nothing more to
    // get it over to the subscriber.
    // We only ack the packet if the resend attempt was successful in getting
    // the packet data into the circular buffer that is consumed by
    // rmc_conn_process_tcp_write()
    if (!res)
        rmc_pub_packet_ack(ctx, conn, pack->pid) ;

    return res;
}


static int process_subscriber_timeout(rmc_pub_context_t* ctx,
                                      pub_subscriber_t* sub,
                                      usec_timestamp_t current_ts)
{
    rmc_connection_t* conn = 0;
    pub_packet_list_t packets;
    pub_packet_t* pack = 0;
    pub_packet_node_t* pnode = 0;
    int res = 0;

    conn = (rmc_connection_t*) pub_subscriber_user_data(sub).ptr;
    pub_packet_list_init(&packets, 0, 0, 0);
    pub_get_timed_out_packets(sub, current_ts, ctx->resend_timeout, &packets);
    RMC_LOG_INDEX_DEBUG(conn->connection_index,
                        "Got [%d] timed out packets to process", pub_packet_list_size(&packets));

    // Traverse packets and send them for timeout. Start
    // with oldest packet first.
    //
    while((pnode = pub_packet_list_head(&packets))) {

        // Outbound circular buffer may be full.
        RMC_LOG_INDEX_DEBUG(conn->connection_index,
                            "Timed out packet pid: %lu", pnode->data->pid);
        if ((res = process_sent_packet_timeout(ctx, sub, pnode->data)) != 0)  {
            pub_packet_list_empty(&packets);
            RMC_LOG_INDEX_DEBUG(conn->connection_index,
                                "process sent packet: %d/%s", res, strerror(res));
            return res;
        }


        // We were successful in queuing the packet transmission.
        pub_packet_list_pop_head(&packets, &pack);
    }

    return 0;
}


int rmc_pub_timeout_process(rmc_pub_context_t* ctx)
{
    usec_timestamp_t current_ts = rmc_usec_monotonic_timestamp();
    pub_sub_list_t subs;
    pub_subscriber_t* sub = 0;
    int res = 0;

    if (!ctx)
        return EINVAL;

    // Check if we need to send an announce packet.
    if (ctx->announce_send_interval &&
        ctx->announce_next_send_ts != 0 &&
        ctx->announce_next_send_ts - current_ts <= 0) {
        char buffer[RMC_MAX_PAYLOAD];
        payload_len_t len = 0;
        uint8_t send_announce = 1;

        // Invoke the callback, if specified, to retrieve a payload to send with the
        // announcement packet.
        // If callback returns 0, do not send announce
        if (ctx->announce_cb)
            send_announce = (*ctx->announce_cb)(ctx, buffer, sizeof(buffer), &len);

        if (len > sizeof(buffer))
            len = sizeof(buffer);

        if (send_announce) {
            RMC_LOG_COMMENT("Sending announce");
            rmc_pub_queue_packet(ctx, buffer, len, 1);
        }

        // Setup next announce.
        if (ctx->announce_send_interval)
            ctx->announce_next_send_ts = current_ts + ctx->announce_send_interval;
        else
            ctx->announce_next_send_ts = 0; // Disable announce sends.

        return 0;
    }

    // Grab a list of subscribers that have timed out packets we need to subscribe
    pub_sub_list_init(&subs, 0, 0, 0);
    pub_get_timed_out_subscribers(&ctx->pub_ctx, current_ts, ctx->resend_timeout, &subs);

    // Traverse the list of subscribers and process their timed out packets
    // by sending them via the TCP control channel.
    while(pub_sub_list_pop_head(&subs, &sub)) {
        res = process_subscriber_timeout(ctx, sub, current_ts);

        if (res) {
            // Clean up the list.
            RMC_LOG_COMMENT("subscriber timeout failed: %s", strerror(res));
            pub_sub_list_empty(&subs);
            return res;
        }
    }

    return 0;
}


int rmc_pub_timeout_get_next(rmc_pub_context_t* ctx, usec_timestamp_t* result_ts)
{
    usec_timestamp_t announce_timeout_ts = -1; // Default is infinite.
    usec_timestamp_t ack_timeout_ts = -1;


    if (!ctx || !result_ts)
        return EINVAL;

    // Default. Not really needed since we will catch
    // all four timeout combos below.
    *result_ts = -1;

    // Get the send timestamp of the oldest packet we have yet to
    // receive an acknowledgement for from the subscriber.
    pub_get_oldest_unackowledged_packet(&ctx->pub_ctx, &ack_timeout_ts);

    // Calculate time stamp of when we need to see an ack by.
    if (ack_timeout_ts != -1)
        ack_timeout_ts += ctx->resend_timeout;

    // Check if we are to send out announce packets.
    if (ctx->announce_next_send_ts != 0)
        announce_timeout_ts = ctx->announce_next_send_ts;


    // Figure out which timeout value to use.
    if (announce_timeout_ts == -1 && ack_timeout_ts == -1) {
        *result_ts = -1;
        return 0;
    }

    if (announce_timeout_ts != -1 && ack_timeout_ts == -1) {
        *result_ts = announce_timeout_ts;
        return 0;
    }

    if (announce_timeout_ts == -1 && ack_timeout_ts != -1) {
        *result_ts = ack_timeout_ts;
        return 0;
    }

    // Both timeout values specified, use the lesser value.
    *result_ts = (ack_timeout_ts < announce_timeout_ts)?ack_timeout_ts:announce_timeout_ts;

    return 0;
}
