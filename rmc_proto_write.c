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



// =============
// SOCKET WRITE
// =============
static int _process_multicast_write(rmc_context_t* ctx)
{
    pub_context_t* pctx = &ctx->pub_ctx;
    pub_packet_t* pack = pub_next_queued_packet(pctx);
    uint8_t packet[RMC_MAX_SOCKETS];
    uint8_t *packet_ptr = packet;
    payload_len_t *hdr_len = (payload_len_t*) packet_ptr;
    packet_id_t pid = 0;
    usec_timestamp_t ts = 0;
    pub_packet_list_t snd_list;
    ssize_t res = 0;

    // Initialize first two bytes (total multticast payload length) to 0.
    *hdr_len = 0;
    packet_ptr += sizeof(payload_len_t);

    pub_packet_list_init(&snd_list, 0, 0, 0);

    while(pack && *hdr_len <= RMC_MAX_SOCKETS) {
        pub_packet_node_t* pnode = 0;

        *((packet_id_t*) packet_ptr) = pack->pid;
        packet_ptr += sizeof(packet_id_t);

        *((payload_len_t*) packet_ptr) = pack->payload_len;
        packet_ptr += sizeof(payload_len_t);

        // FIXME: Replace with sendmsg() to get scattered iovector
        //        write.  Saves one memcpy.
        memcpy(packet_ptr, pack->payload, pack->payload_len);
        packet_ptr += pack->payload_len;

        *hdr_len += sizeof(packet_id_t) + sizeof(payload_len_t) + pack->payload_len;

        pub_packet_list_push_head(&snd_list, pack);
        pnode = pub_packet_list_next(pack->parent_node);
        pack = pnode?pnode->data:0;
    }

    res = sendto(ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].descriptor,
                 packet,
                 sizeof(payload_len_t) + *hdr_len,
                 MSG_DONTWAIT,
                 (struct sockaddr*) &ctx->mcast_dest_addr,
                 sizeof(ctx->mcast_dest_addr));

    if (res == -1) {
        if ( errno != EAGAIN && errno != EWOULDBLOCK)
            return errno;

        // Would block. Re-arm and return success.
        ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].poll_info.action = RMC_POLLREAD | RMC_POLLWRITE;
        return 0;
    }


    ts = rmc_usec_monotonic_timestamp();

    // Mark all packages in the multicast packet we just
    // sent in the multicast message as sent.
    // pub_packet_sent will call free_o
    while(pub_packet_list_pop_head(&snd_list, &pack))
        pub_packet_sent(pctx, pack, ts);

    // Do we have more packets to send? If so, rearm new action
    // with both read and write.
    ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].poll_info.action =
        RMC_POLLREAD | (pub_next_queued_packet(pctx)?RMC_POLLWRITE:0);

    return 0;
}


static int _process_tcp_write(rmc_context_t* ctx, rmc_socket_t* sock, uint32_t* bytes_left)
{
    uint8_t *seg1 = 0;
    uint32_t seg1_len = 0;
    uint8_t *seg2 = 0;
    uint32_t seg2_len = 0;
    struct iovec iov[2];
    ssize_t res = 0;

    // Grab as much data as we can.
    // The call will only return available
    // data.
    circ_buf_read_segment(&sock->write_buf,
                          sizeof(sock->write_buf_data),
                          &seg1, &seg1_len,
                          &seg2, &seg2_len);

    if (!seg1_len) {
        *bytes_left = 0;
        return ENODATA;
    }
    
    // Setup a zero-copy scattered socket write
    iov[0].iov_base = seg1;
    iov[0].iov_len = seg1_len;
    iov[1].iov_base = seg2;
    iov[1].iov_len = seg2_len;

    errno = 0;
    res = writev(sock->descriptor, iov, seg2_len?2:1);

    // How did that write go?
    if (res == -1) { 
        *bytes_left = circ_buf_in_use(&sock->write_buf);
        return errno;
    }

    if (res == 0) { 
        *bytes_left = circ_buf_in_use(&sock->write_buf);
        return 0;
    }

    // We wrote a specific number of bytes, free those
    // bytes from the circular buffer.
    // At the same time grab number of bytes left to
    // send from the buffer.,
    circ_buf_free(&sock->write_buf, res, bytes_left);

    return 0;
}

int rmc_write(rmc_context_t* ctx, rmc_poll_index_t p_ind)
{
    int res = 0;
    int rearm_write = 0;
    uint32_t bytes_left_before = 0;
    uint32_t bytes_left_after = 0;
    rmc_poll_t old_info;
    assert(ctx);

    if (p_ind == RMC_MULTICAST_SOCKET_INDEX) {
        res = _process_multicast_write(ctx);
        return res;
    }

    // Is p_ind within our socket vector?
    if (p_ind < 2 || p_ind >= RMC_MAX_SOCKETS)
        return EINVAL;

    if (ctx->sockets[p_ind].descriptor == -1)
        return ENOTCONN;

    // We have incoming data on a tcp socket.
    if (circ_buf_in_use(&ctx->sockets[p_ind].write_buf) == 0) 
        return ENODATA;

    res = _process_tcp_write(ctx, &ctx->sockets[p_ind], &bytes_left_after);
    
    old_info = ctx->sockets[p_ind].poll_info;
    if (bytes_left_after == 0) 
        ctx->sockets[p_ind].poll_info.action &= ~RMC_POLLWRITE;
    else
        ctx->sockets[p_ind].poll_info.action |= RMC_POLLWRITE;

    if (ctx->poll_modify)
        (*ctx->poll_modify)(&old_info, &ctx->sockets[p_ind].poll_info);

    return res;
}


int rmc_proto_ack(rmc_context_t* ctx, rmc_socket_t* sock, sub_packet_t* pack)
{
    uint32_t available = circ_buf_available(&sock->write_buf);
    uint32_t old_in_use = circ_buf_in_use(&sock->write_buf);
    rmc_poll_t old_poll_info = sock->poll_info;
    ssize_t res = 0;
    uint8_t *seg1 = 0;
    uint32_t seg1_len = 0;
    uint8_t *seg2 = 0;
    uint32_t seg2_len = 0;
    cmd_ack_single_t ack = {
        .packet_id = pack->pid
    };

    if (!ctx || !sock || !pack || sock->mode != RMC_SOCKET_MODE_SUBSCRIBER) 
        return EINVAL;

    // Allocate memory for command
    circ_buf_alloc(&sock->write_buf, 1,
                   &seg1, &seg1_len,
                   &seg2, &seg2_len);


    *seg1 = RMC_CMD_ACK_SINGLE;

    // Allocate memory for packet header
    circ_buf_alloc(&sock->write_buf, sizeof(ack) ,
                   &seg1, &seg1_len,
                   &seg2, &seg2_len);


    // Copy in packet header
    memcpy(seg1, (uint8_t*) &ack, seg1_len);
    if (seg2_len) 
        memcpy(seg2, ((uint8_t*) &ack) + seg1_len, seg2_len);

    // Do we need to arm the write poll descriptor.
    if (!old_in_use) {
            // Read poll is always active. Callback to re-arm.
        sock->poll_info.action |= RMC_POLLWRITE;
        if (ctx->poll_modify)
            (*ctx->poll_modify)(&old_poll_info,
                                &sock->poll_info);
    }
    
}

