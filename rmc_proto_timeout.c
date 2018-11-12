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


// =============
// TIMEOUT MANAGEMENT
// =============
static int _process_packet_timeout(rmc_context_t* ctx,
                                   pub_subscriber_t* sub,
                                   pub_packet_t* pack,
                                   usec_timestamp_t timeout_ts)
{
    // Send the packet via TCP.
    rmc_connection_t* conn = 0;
    uint8_t *seg1 = 0;
    uint32_t seg1_len = 0;
    uint8_t *seg2 = 0;
    uint32_t seg2_len = 0;
    int res = 0;
    uint8_t cmd = RMC_CMD_PACKET;
    cmd_packet_header_t pack_cmd = {
        .pid = pack->pid,
        .payload_len = pack->payload_len
    };
    
    if (!ctx || !sub || !pack)
        return EINVAL;

    conn = (rmc_connection_t*) pub_packet_user_data(pack).ptr;
    if (!conn || conn->mode != RMC_CONNECTION_MODE_PUBLISHER)
        return EINVAL;
        
    // Do we have enough circular buffer meomory available?
    if (circ_buf_available(&conn->write_buf) < 1 + sizeof(pack) + pack->payload_len)
        return ENOMEM;
    
    // Allocate memory for command
    circ_buf_alloc(&conn->write_buf, 1,
                   &seg1, &seg1_len,
                   &seg2, &seg2_len);


    *seg1 = cmd;

    // Allocate memory for packet header
    circ_buf_alloc(&conn->write_buf, sizeof(pack_cmd) ,
                   &seg1, &seg1_len,
                   &seg2, &seg2_len);


    // Copy in packet header
    memcpy(seg1, (uint8_t*) &pack_cmd, seg1_len);
    if (seg2_len) 
        memcpy(seg2, ((uint8_t*) &pack_cmd) + seg1_len, seg2_len);

    // Allocate packet payload
    circ_buf_alloc(&conn->write_buf, sizeof(pack),
                   &seg1, &seg1_len,
                   &seg2, &seg2_len);


    // Copy in packet header
    memcpy(seg1, pack->payload, seg1_len);
    if (seg2_len) 
        memcpy(seg2, ((uint8_t*) pack->payload) + seg1_len, seg2_len);

    // Setup the poll write action
    if (!(conn->action & RMC_POLLWRITE)) {
        rmc_poll_action_t old_action = conn->action;

        conn->action |= RMC_POLLWRITE;
        if (ctx->poll_modify)
            (*ctx->poll_modify)(ctx,
                                conn->descriptor,
                                conn->connection_index,
                                old_action,
                                conn->action);
    }    
    
    return 0;
}


static int _process_subscriber_timeout(rmc_context_t* ctx, pub_subscriber_t* sub, usec_timestamp_t timeout_ts)
{
    pub_packet_list_t packets;
    pub_packet_t* pack = 0;
    pub_packet_node_t* pnode = 0;
    int res = 0;

    pub_packet_list_init(&packets, 0, 0, 0);
    pub_get_timed_out_packets(sub, timeout_ts, &packets);

    // Traverse packets and send them for timeout. Start
    // with oldest packet first.
    while((pnode = pub_packet_list_tail(&packets))) {
        // Outbound circular buffer may be full.
        if ((res = _process_packet_timeout(ctx, sub, pnode->data, timeout_ts)) != 0)
            return res;

        // We were successful in queuing the packet transmission.
        pub_packet_list_pop_tail(&packets, &pack);
    }

    return 0;
}


int rmc_process_timeout(rmc_context_t* ctx)
{
    usec_timestamp_t ts = rmc_usec_monotonic_timestamp();
    pub_sub_list_t subs;
    pub_subscriber_t* sub = 0;
    int res = 0;
    
    if (!ctx)
        return EINVAL;
    
    pub_sub_list_init(&subs, 0, 0, 0);
    pub_get_timed_out_subscribers(&ctx->pub_ctx, ts - ctx->resend_timeout, &subs);

    while(pub_sub_list_pop_head(&subs, &sub)) {
        res = _process_subscriber_timeout(ctx, sub, ts - ctx->resend_timeout);

        if (res) {
            // Clean up the list.
            while(pub_sub_list_pop_head(&subs, &sub))
                ;

            return res;
        }
    }
    return 0;
}


int rmc_get_next_timeout(rmc_context_t* ctx, usec_timestamp_t* result)
{
    usec_timestamp_t ts = rmc_usec_monotonic_timestamp();
    pub_subscriber_t* sub = 0;
    pub_packet_t* pack = 0;

    if (!ctx || !result)
        return EINVAL;
    
    // Get the oldest packet, and its subscriber, with the
    // oldest pending ack that we haven't seen yet.
    pub_get_oldest_unackowledged_packet(&ctx->pub_ctx, &sub, &pack);

    // If no subscriber has inflight packets, then set result to -1.
    if (!sub) {
        *result = -1;
        return ENODATA;
    }

    // Has our oldest packet already expired?
    if (pack->send_ts <= ts - ctx->resend_timeout) {
        *result = 0;
        return 0;
    }

    *result =  (ts - ctx->resend_timeout) - (ts - pack->send_ts);
    return 0;
}




