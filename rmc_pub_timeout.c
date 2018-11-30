// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)



#define _GNU_SOURCE
#include "reliable_multicast.h"
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

// =============
// TIMEOUT MANAGEMENT
// =============


static int _process_sent_packet_timeout(rmc_pub_context_t* ctx,
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
    printf("process_sent_packet_timeout(): pid[%lu] mcast[%s:%d] listen[%s:%d]\n",
           pack->pid,
           group_addr,
           ctx->mcast_port,
           remote_addr,
           ctx->control_listen_port);
    
    if (!conn || conn->mode != RMC_CONNECTION_MODE_PUBLISHER)
        return EINVAL;
        
    res = _rmc_pub_resend_packet(ctx, conn, pack);
    rmc_pub_packet_ack(ctx, conn, pack->pid) ;
    return res;
}


static int _process_subscriber_timeout(rmc_pub_context_t* ctx,
                                       pub_subscriber_t* sub,
                                       usec_timestamp_t current_ts)
{
    pub_packet_list_t packets;
    pub_packet_t* pack = 0;
    pub_packet_node_t* pnode = 0;
    int res = 0;

    pub_packet_list_init(&packets, 0, 0, 0);
    pub_get_timed_out_packets(sub, current_ts, ctx->resend_timeout, &packets);

    // Traverse packets and send them for timeout. Start
    // with oldest packet first.
    while((pnode = pub_packet_list_tail(&packets))) {
        // Outbound circular buffer may be full.
        printf("Timed out packet: %lu\n", pnode->data->pid);
        if ((res = _process_sent_packet_timeout(ctx, sub, pnode->data)) != 0)
            return res;

        // We were successful in queuing the packet transmission.
        pub_packet_list_pop_tail(&packets, &pack);

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
    if (ctx->announce_next_send_ts != 0 && ctx->announce_next_send_ts - current_ts <= 0) {
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
            puts("Sendning out announcement");
            rmc_pub_queue_packet(ctx, buffer, len, 1);
        }

        // Setup next announce.
        if (ctx->announce_send_interval) 
            ctx->announce_next_send_ts = current_ts + ctx->announce_send_interval;
        else
            ctx->announce_next_send_ts = 0; // Disable announce sends.

        return 0;
    }

    pub_sub_list_init(&subs, 0, 0, 0);
    pub_get_timed_out_subscribers(&ctx->pub_ctx, current_ts, ctx->resend_timeout, &subs);

    while(pub_sub_list_pop_head(&subs, &sub)) {
        res = _process_subscriber_timeout(ctx, sub, current_ts);

        if (res) {
            // Clean up the list.
            while(pub_sub_list_pop_head(&subs, &sub))
                ;

            return res;
        }
    }

    return 0;
}


int rmc_pub_timeout_get_next(rmc_pub_context_t* ctx, usec_timestamp_t* result)
{
    usec_timestamp_t oldest_sent_ts = 0;
    usec_timestamp_t current_ts = rmc_usec_monotonic_timestamp();
    usec_timestamp_t announce_timeout = -1;
    usec_timestamp_t ack_timeout = -1;

    if (!ctx || !result)
        return EINVAL;
    

    // Check if we are to send out announce packets.
    if (ctx->announce_next_send_ts != 0) {
        announce_timeout =  ctx->announce_next_send_ts - current_ts;
        if (announce_timeout < 0)
            announce_timeout = 0;
    }

    // Figure out which timeout value to use.
    if (announce_timeout == -1 && ack_timeout == -1) {
        *result = -1;
        return 0;
    }

    if (announce_timeout != -1 && ack_timeout == -1) {
        *result = announce_timeout;
        return 0;
    }

    if (announce_timeout == -1 && ack_timeout != -1) {
        *result = ack_timeout;
        return 0;
    }

    // Both timeout values specified, use the lesser value.
    *result = (ack_timeout < announce_timeout)?ack_timeout:announce_timeout;

    // Get the send timestamp of the oldest packet we have yet to
    // receive an acknowledgement for from the subscriber.
    pub_get_oldest_unackowledged_packet(&ctx->pub_ctx, &oldest_sent_ts);

    
    // Did we have infinite timeout?
    if (oldest_sent_ts == -1) {
        *result = -1;
        return 0;
    }
        
    // Convert to millisecond from now that it times out
    oldest_sent_ts = oldest_sent_ts + ctx->resend_timeout - current_ts;
    if (oldest_sent_ts < 0)
        oldest_sent_ts = 0;
    
    *result = oldest_sent_ts;
    return 0;
}
