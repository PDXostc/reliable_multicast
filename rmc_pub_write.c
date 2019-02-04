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
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <assert.h>


static void setup_packet_header(rmc_pub_context_t* ctx,
                                pub_packet_t* pack,
                                packet_header_t* pack_hdr)
{
    // Setup node id.
    pack_hdr->node_id = ctx->node_id;
    pack_hdr->payload_len = pack->payload_len;
    pack_hdr->pid = pack->pid;

    // If listen_ip == 0 then receiver will use source address of packet as tcp
    // address to connect to.
    pack_hdr->listen_ip = ctx->control_listen_if_addr;
    pack_hdr->listen_port = ctx->control_listen_port;
}

// FIXME: If we see timed out (== lost) packets from subscribers, we should
//        switch them to TCP for a period of time in order
//        to use TCP's flow control until congestion has eased.
static int send_single_multicast_packet(rmc_pub_context_t* ctx, pub_packet_t* pack)
{
    pub_context_t* pctx = &ctx->pub_ctx;
    uint8_t packet[RMC_MAX_PACKET];
    uint8_t *packet_ptr = packet;
    packet_id_t pid = 0;
    usec_timestamp_t ts = 0;
    ssize_t res = 0;
    packet_header_t pack_hdr;
    struct msghdr msg_hdr;
    struct iovec io_vec[2];
    struct sockaddr_in sock_addr = (struct sockaddr_in) {
        .sin_family = AF_INET,
        .sin_port = htons(ctx->mcast_port),
        .sin_addr = (struct in_addr) { .s_addr = htonl(ctx->mcast_group_addr) }
    };


    if (ctx->mcast_send_descriptor == -1)
        return ENOTCONN;

    // Will the packet fit inside a UDP packet?
    if (sizeof(packet_header_t) + pack->payload_len > RMC_MAX_PACKET)
        return EMSGSIZE;

    setup_packet_header(ctx, pack, &pack_hdr);

//    char listen_addr[128];
//    char mcast_addr[128];
//    strcpy(listen_addr, inet_ntoa( (struct in_addr) { .s_addr = htonl(ctx->control_listen_if_addr) }));
//    strcpy(mcast_addr, inet_ntoa( (struct in_addr) { .s_addr = htonl(ctx->mcast_group_addr) }));
//    printf("mcast_tx(): mcast[%s:%d] listen[%s:%d] pid[%lu:%lu] - len[%.5lu]\n",
//           mcast_addr, ntohs(sock_addr.sin_port),
//           listen_addr, pack_hdr->listen_port,
//           first_sent, last_sent, sizeof(packet_header_t) + pack_hdr->payload_len);

    // Setup the scattered-write io vector with header and payload
    io_vec[0] = (struct iovec) {
        .iov_base = (void*) &pack_hdr,
        .iov_len = sizeof(pack_hdr)
    };

    io_vec[1] = (struct iovec) {
        .iov_base = (void*) pack->payload,
        .iov_len = pack->payload_len
    };

    // Setup message header.
    msg_hdr = (struct msghdr) {
        .msg_name = (void*) &sock_addr,
        .msg_namelen = sizeof(sock_addr),
        .msg_iov = io_vec,
        .msg_iovlen = sizeof(io_vec) / sizeof(io_vec[0]),
        .msg_control = 0,
        .msg_controllen = 0,
        .msg_flags = 0
    };

    res = sendmsg(ctx->mcast_send_descriptor, &msg_hdr, MSG_DONTWAIT);

    if (res == -1) {
        if ( errno != EAGAIN && errno != EWOULDBLOCK) {
            RMC_LOG_INDEX_WARNING(RMC_MULTICAST_INDEX,
                                  "sendmsg(): %d/%s", errno, strerror(errno));
            return errno;
        }

        // We are ok with an EAGAIN error since we can retry later to
        // send the packet.

        res = EAGAIN;
        goto rearm;
    }

    pub_packet_sent(pctx, pack, rmc_usec_monotonic_timestamp());

    res = 0;
rearm:
    if (ctx->conn_vec.poll_modify) {
        // Do we have more packets to send?
        (*ctx->conn_vec.poll_modify)(ctx->user_data,
                            ctx->mcast_send_descriptor,
                            RMC_MULTICAST_INDEX,
                            RMC_POLLWRITE,
                            pub_next_queued_packet(pctx)?RMC_POLLWRITE:0);
    }
    return res;
}


static int process_multicast_write(rmc_pub_context_t* ctx)
{
    pub_context_t* pctx = &ctx->pub_ctx;
    pub_packet_t* pack = pub_next_queued_packet(pctx);
    int res = 0;
    int count = 0;

    while(pack) {
        if ((res = send_single_multicast_packet(ctx, pack)))
            break;

        ++count;
        pack = pub_next_queued_packet(pctx);
    }

    return res;
}


int rmc_pub_resend_packet(rmc_pub_context_t* ctx,
                           rmc_connection_t* conn,
                           pub_packet_t* pack)
{
    uint8_t *seg1 = 0;
    uint32_t seg1_len = 0;
    uint8_t *seg2 = 0;
    uint32_t seg2_len = 0;
    int res = 0;
    packet_header_t pack_hdr;

    // Do we have enough circular buffer meomory available?
    if (circ_buf_available(&conn->write_buf) < 1 + sizeof(packet_header_t) + pack->payload_len) {
        RMC_LOG_INDEX_DEBUG(conn->connection_index,
                            "Resend packet needed %d+%d+%d=%d bytes, got %d",
                            1, sizeof(packet_header_t),pack->payload_len,
                            1 + sizeof(packet_header_t) + pack->payload_len,
                            circ_buf_available(&conn->write_buf));
        res = EAGAIN;
        goto rearm;
    }

    // Allocate memory for command
    res = circ_buf_alloc(&conn->write_buf, 1,
                         &seg1, &seg1_len,
                         &seg2, &seg2_len);

    // We checked above that we have memory, so an error here is final
    if (res) {
        RMC_LOG_INDEX_FATAL(conn->connection_index,
                            "Could not allocate one byte: %s\n", strerror(errno));
        exit(255);
    }
    *seg1 = RMC_CMD_PACKET;

    setup_packet_header(ctx, pack, &pack_hdr);

    // Allocate memory for packet header
    res = circ_buf_alloc(&conn->write_buf, sizeof(packet_header_t),
                         &seg1, &seg1_len,
                         &seg2, &seg2_len);

    if (res) {
        RMC_LOG_INDEX_FATAL(conn->connection_index,
                            "Could not allocate %lu header bytes: %s\n", sizeof(pack_hdr), strerror(errno));
        exit(255);
    }

    // Copy in packet header
    memcpy(seg1, (uint8_t*) &pack_hdr, seg1_len);
    if (seg2_len)
        memcpy(seg2, ((uint8_t*) &pack_hdr) + seg1_len, seg2_len);

    // Allocate packet payload
    res = circ_buf_alloc(&conn->write_buf, pack->payload_len,
                         &seg1, &seg1_len,
                         &seg2, &seg2_len);

    if (res) {
        RMC_LOG_INDEX_FATAL(conn->connection_index,
                      "Could not allocate %d payload bytes: %s\n", pack->payload_len, strerror(errno));
        exit(255);
    }

    // Copy in packet payload
    memcpy(seg1, pack->payload, seg1_len);
    if (seg2_len)
        memcpy(seg2, ((uint8_t*) pack->payload) + seg1_len, seg2_len);

    RMC_LOG_INDEX_DEBUG(conn->connection_index,
                  "Queued %d bytes",
                 1 + sizeof(packet_header_t) + pack->payload_len);

rearm:
    // Setup the poll write action
    if (!(conn->action & RMC_POLLWRITE)) {
        rmc_poll_action_t old_action = conn->action;

        conn->action |= RMC_POLLWRITE;
        if (ctx->conn_vec.poll_modify)
            (*ctx->conn_vec.poll_modify)(ctx->user_data,
                                         conn->descriptor,
                                         conn->connection_index,
                                         old_action,
                                         conn->action);
    }

    return res;
}


int rmc_pub_write(rmc_pub_context_t* ctx, rmc_index_t s_ind, uint8_t* op_res)
{
    int res = 0;
    int rearm_write = 0;
    uint32_t bytes_left_before = 0;
    uint32_t bytes_left_after = 0;
    rmc_poll_action_t old_action = 0;
    rmc_connection_t* conn = 0;
    assert(ctx);

    if (s_ind == RMC_MULTICAST_INDEX) {
        if (op_res)
            *op_res = RMC_WRITE_MULTICAST;
        // Write as many multicast packets as we can.
        RMC_LOG_INDEX_DEBUG(RMC_MULTICAST_INDEX,
                            "Processing multicast write");
        return process_multicast_write(ctx);
    }

    // Is s_ind within our connection vector?
    if (s_ind >= rmc_pub_get_max_subscriber_count(ctx)) {
        if (op_res)
            *op_res = RMC_ERROR;

        return EINVAL;
    }

    conn = rmc_conn_find_by_index(&ctx->conn_vec, s_ind);

    if (!conn || conn->mode != RMC_CONNECTION_MODE_CONNECTED) {
        if (op_res)
            *op_res = RMC_ERROR;

        return ENOTCONN;
    }


    old_action = conn->action;

    // Do we have any data to write?
    if (circ_buf_in_use(&conn->write_buf) == 0) {
        if (op_res)
            *op_res = RMC_ERROR;

        return ENODATA;
    }

    if (op_res)
        *op_res = RMC_WRITE_TCP;

    res = rmc_conn_process_tcp_write(conn, &bytes_left_after);

    if (bytes_left_after == 0)
        conn->action &= ~RMC_POLLWRITE;
    else
        conn->action |= RMC_POLLWRITE;

    if (ctx->conn_vec.poll_modify)
        (*ctx->conn_vec.poll_modify)(ctx->user_data,
                                     conn->descriptor,
                                     s_ind,
                                     old_action,
                                     conn->action);

    // Did we encounter an error.
    if (res && op_res)
        *op_res = RMC_ERROR;

    return res;
}


// FIXME MEDIUM: Not the fastest. But this function
// *should* mostly be used during shutdown.

int rmc_pub_context_get_pending(rmc_pub_context_t* ctx,
                                uint32_t* queued_packets,
                                uint32_t* send_buf_len,
                                uint32_t* ack_count)
{
    payload_len_t len = 0;
    rmc_index_t ind = 0;
    int count = 0;
    rmc_index_t max_ind = 0;
    uint8_t busy = 0;
    uint32_t queue_size = 0;

    if (!ctx)
        EINVAL;

    if (ack_count)
        *ack_count = 0;

    if (send_buf_len)
        *send_buf_len = 0;

    queue_size = pub_queue_size(&ctx->pub_ctx);
    if (queue_size > 0)
        busy = 1;

    if (queued_packets)
        *queued_packets = queue_size;

    rmc_conn_get_max_index_in_use(&ctx->conn_vec, &max_ind);

    // If we have no subscribers, just return immediately
    if (max_ind == -1)
        // Return EBUSY if we have pending data to transmit
        return busy?EBUSY:0;

    for(ind = 0; ind <= max_ind; ++ind) {
        rmc_connection_t* conn = 0;
        pub_subscriber_t *sub = 0;
        payload_len_t len = 0;

        conn = rmc_conn_find_by_index(&ctx->conn_vec, ind);

        if (!conn)
            continue;

        sub = &ctx->subscribers[conn->connection_index];

        count = pub_packet_list_size(&sub->inflight);
        if (count != 0) {
            busy = 1;

            if (ack_count)
                *ack_count += count;
        }


        rmc_conn_get_pending_send_length(conn, &len);

        if (len != 0) {
            busy = 1;

            if (send_buf_len)
                *send_buf_len += len;
        }
    }

    // Return EBUSY if we have pending data to transmit
    return busy?EBUSY:0;
}
