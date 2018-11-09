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


// FIXME: If we see timed out (== lost) packets from subscribers, we should
//        switch them to TCP for a period of time in order
//        to use TCP's flow control until congestion has eased.



// =============
// SOCKET WRITE
// =============
static int _process_multicast_write(rmc_context_t* ctx)
{
    pub_context_t* pctx = &ctx->pub_ctx;
    pub_packet_t* pack = pub_next_queued_packet(pctx);
    uint8_t packet[RMC_MAX_PAYLOAD];
    uint8_t *packet_ptr = packet;
    packet_id_t pid = 0;
    usec_timestamp_t ts = 0;
    pub_packet_list_t snd_list;
    ssize_t res = 0;
    multicast_header_t *mcast_hdr = (multicast_header_t*) packet_ptr;
    char* listen_addr = 0;
    char* mcast_addr = 0;
    struct sockaddr_in sock_addr = (struct sockaddr_in) {
        .sin_family = AF_INET,
        .sin_port = htons(ctx->mcast_port),
        .sin_addr = (struct in_addr) { .s_addr = htonl(ctx->mcast_group_addr) }
    };

    if (ctx->mcast_send_descriptor == -1)
        return ENOTCONN;

    // Setup context id. 
    mcast_hdr->context_id = ctx->context_id;
    mcast_hdr->payload_len = 0; // Will be updated below

    // If listen_ip == 0 then receiver will use source address of packet as tcp
    // address to connect to.
    mcast_hdr->listen_ip = ctx->listen_if_addr; 
    mcast_hdr->listen_port = ctx->listen_port; 

    packet_ptr += sizeof(multicast_header_t);

    pub_packet_list_init(&snd_list, 0, 0, 0);

    listen_addr = inet_ntoa( (struct in_addr) { .s_addr = htonl(ctx->listen_if_addr) });
    mcast_addr = inet_ntoa( (struct in_addr) { .s_addr = htonl(ctx->mcast_group_addr) });

    while(pack && mcast_hdr->payload_len <= RMC_MAX_PAYLOAD) {
        pub_packet_node_t* pnode = 0;
        cmd_packet_header_t* cmd_pack = (cmd_packet_header_t*) packet_ptr;

        cmd_pack->pid = pack->pid;
        cmd_pack->payload_len = pack->payload_len;
        packet_ptr += sizeof(cmd_packet_header_t);

        // FIXME: Replace with sendmsg() to get scattered iovector
        //        write.  Saves one memcpy.
        memcpy(packet_ptr, pack->payload, pack->payload_len);
        packet_ptr += pack->payload_len;

        mcast_hdr->payload_len += sizeof(cmd_packet_header_t) + pack->payload_len;

        pub_packet_list_push_head(&snd_list, pack);

        // FIXME: Maybe add a specific API call to traverse queued packages?
        pnode = pub_packet_list_prev(pack->parent_node);
        pack = pnode?pnode->data:0;
    }

    printf("mcast_tx(): ctx_id[0x%.8X] len[%.5d] mcast[%s:%d] listen[%s:%d]\n",
           mcast_hdr->context_id,
           mcast_hdr->payload_len,
           mcast_addr, ntohs(sock_addr.sin_port),
           listen_addr, mcast_hdr->listen_port);

    res = sendto(ctx->mcast_send_descriptor,
                 packet,
                 sizeof(multicast_header_t) + mcast_hdr->payload_len,
                 MSG_DONTWAIT,
                 (struct sockaddr*) &sock_addr,
                 sizeof(sock_addr));

    if (res == -1) {
        if ( errno != EAGAIN && errno != EWOULDBLOCK)
            return errno;

        if (ctx->poll_modify) {
            (*ctx->poll_modify)(ctx,
                                ctx->mcast_send_descriptor,
                                RMC_MULTICAST_SEND_INDEX,
                                RMC_POLLWRITE,
                                RMC_POLLWRITE);
        }
        return 0;
    }

    ts = rmc_usec_monotonic_timestamp();

    // Mark all packages in the multicast packet we just
    // sent in the multicast message as sent.
    // pub_packet_sent will call free_o
    while(pub_packet_list_pop_head(&snd_list, &pack)) {
        printf("inflight[%lu]\n", pack->pid);
        pub_packet_sent(pctx, pack, ts);
    }

    extern void test_print_context(pub_context_t* ctx);
    test_print_context(&ctx->pub_ctx);

    if (ctx->poll_modify) {
        // Do we have more packets to send?
        (*ctx->poll_modify)(ctx,
                            ctx->mcast_send_descriptor,
                            RMC_MULTICAST_SEND_INDEX,
                            RMC_POLLWRITE,
                            pub_next_queued_packet(pctx)?RMC_POLLWRITE:0);
    }
    return 0;
}


static int _process_tcp_write(rmc_context_t* ctx, rmc_connection_t* sock, uint32_t* bytes_left)
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

int rmc_write(rmc_context_t* ctx, rmc_connection_index_t s_ind)
{
    int res = 0;
    int rearm_write = 0;
    uint32_t bytes_left_before = 0;
    uint32_t bytes_left_after = 0;
    rmc_poll_action_t old_action;
    rmc_connection_t* sock = 0;
    assert(ctx);


    if (s_ind == RMC_MULTICAST_SEND_INDEX) {
        return _process_multicast_write(ctx);
    }

    // Is s_ind within our connection vector?
    if (s_ind >= RMC_MAX_CONNECTIONS)
        return EINVAL;

    sock = &ctx->connections[s_ind];

    if (sock->descriptor == -1)
        return ENOTCONN;


    // Is this socket in the process of being connected
    if (sock->mode == RMC_CONNECTION_MODE_CONNECTING) {
        rmc_complete_connect(ctx, sock);
        return 0;
    }

    old_action = ctx->connections[s_ind].action;

    // Do we have any data to write?
    if (circ_buf_in_use(&ctx->connections[s_ind].write_buf) == 0) 
        return ENODATA;

    res = _process_tcp_write(ctx, &ctx->connections[s_ind], &bytes_left_after);
    
    if (bytes_left_after == 0) 
        ctx->connections[s_ind].action &= ~RMC_POLLWRITE;
    else
        ctx->connections[s_ind].action |= RMC_POLLWRITE;

    if (ctx->poll_modify)
        (*ctx->poll_modify)(ctx,
                            ctx->connections[s_ind].descriptor,
                            s_ind,
                            old_action,
                            ctx->connections[s_ind].action);

    return res;
}

// Send an ack for a packet that has been processed.
// Called by rmc_free_packet().
int rmc_proto_ack(rmc_context_t* ctx, rmc_connection_t* sock, sub_packet_t* pack)
{
    uint32_t available = circ_buf_available(&sock->write_buf);
    uint32_t old_in_use = circ_buf_in_use(&sock->write_buf);
    rmc_poll_action_t old_action = sock->action;
    ssize_t res = 0;
    uint8_t *seg1 = 0;
    uint32_t seg1_len = 0;
    uint8_t *seg2 = 0;
    uint32_t seg2_len = 0;
    cmd_ack_single_t ack = {
        .packet_id = pack->pid
    };

    if (!ctx || !sock || !pack || sock->mode != RMC_CONNECTION_MODE_SUBSCRIBER) 
        return EINVAL;

    printf("ack(): ctx_id[0x%.8X] pid[%lu] mcast[%s:%d] listen[%s:%d]\n",
           ctx->context_id,
           pack->pid,
           inet_ntoa( (struct in_addr) { .s_addr = htonl(ctx->mcast_group_addr) }),
           ctx->mcast_port,
           inet_ntoa( (struct in_addr) { .s_addr = htonl(sock->remote_address) }),
           sock->remote_port);


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

    // We always want to read from the tcp  socket.
    sock->action = RMC_POLLREAD;

    // Do we need to arm the write poll descriptor.
    if (!old_in_use) 
        sock->action |= RMC_POLLWRITE;

    if (ctx->poll_modify)
        (*ctx->poll_modify)(ctx,
                            sock->descriptor,
                            sock->rmc_index,
                            old_action,
                            sock->action);
    
}
