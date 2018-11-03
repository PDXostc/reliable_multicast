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

static inline rmc_socket_t* _find_publisher_by_address(rmc_context_t* ctx,
                                                       struct sockaddr_in* addr)
{
    rmc_poll_index_t ind = 0;

    // Do we have any sockets in use at all?
    if (ctx->max_socket_ind == -1)
        return 0;
    
    // FIXME: Replace with hash table search to speed up.
    while(ind < ctx->max_socket_ind) {
        if (ctx->sockets[ind].poll_info.descriptor != -1 &&
            !memcmp(&ctx->sockets[ind].remote_address, addr, sizeof(*addr)))
            return &ctx->sockets[ind];

        ++ind;
    }
    return 0;
}

static int _decode_multicast(rmc_context_t* ctx,
                             uint8_t* packet,
                             ssize_t packet_len,
                             sub_publisher_t* pub)
{
    payload_len_t len = (payload_len_t) packet_len;

    // Traverse the received datagram and extract all packets
    while(len) {
        void* payload = 0;
        packet_id_t pid = 0;
        payload_len_t payload_len = 0;

        
        pid = *(packet_id_t*) packet;
        packet += sizeof(packet_id_t);

        payload_len = *(payload_len_t*) packet;
        packet += sizeof(payload_len_t);
        len -= (payload_len + sizeof(pid) + sizeof(payload_len));

        // Check that we do not have a duploic
        if (sub_packet_is_duplicate(pub, pid))
            continue;

        // Use the provided memory allocator to reserve memory for
        // incoming payload.
        // Use malloc() if nothing is specified.
        if (ctx->payload_alloc)
            payload = (*ctx->payload_alloc)(ctx, payload_len);
        else
            payload = malloc(payload_len);

        if (!payload)
            return ENOMEM;

        memcpy(payload, packet, payload_len);
        packet += payload_len;

        sub_packet_received(pub, pid, payload, payload_len);
    }

    // Process received packages, moving consectutive ones
    // over to the ready queue.
    sub_process_received_packets(pub);

    return 0;
}

static int _process_multicast_read(rmc_context_t* ctx)
{
    uint8_t buffer[RMC_MAX_PAYLOAD];
    uint8_t *data = buffer;
    payload_len_t payload_len;
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    ssize_t res;
    int sock_ind = 0;
    rmc_socket_t* sock = 0;
    rmc_context_id_t ctx_id = 0;
    rmc_poll_t pinfo = {
        .action = RMC_POLLREAD,
        .descriptor = ctx->mcast_recv_descriptor,
        .rmc_index = RMC_MULTICAST_RECV_INDEX
    };

    if (!ctx)
        return EINVAL;

    if (ctx->mcast_recv_descriptor == -1)
        return ENOTCONN;

    res = recvfrom(ctx->mcast_recv_descriptor,
                   buffer, sizeof(buffer),
                   0,
                   (struct sockaddr*) &src_addr, &addr_len);

    if (res == -1) {
        perror("rmc_proto::rmc_read_multicast(): recvfrom()");
        return errno;
    }


    printf("_process_multicast_read(): %s:%d\n", inet_ntoa(src_addr.sin_addr), ntohs(src_addr.sin_port));

    ctx_id = *(rmc_context_id_t*) data;
    data += sizeof(rmc_context_id_t);

    payload_len = *(payload_len_t*) data;
    data += sizeof(payload_len_t);
    
    // FIXME: REMOVE WHEN WE HAVE DELETED IP_MULTICAST_LOOP
    if (ctx_id == ctx->context_id) {
        printf("_process_multicast_read(): Skipping loopback message\n");
        if (ctx->poll_modify)
            (*ctx->poll_modify)(ctx, &pinfo, &pinfo);
    }

    sock = _find_publisher_by_address(ctx, &src_addr);

    // No publisher found?
    if (!sock) {
        // Add an outbound tcp connection to the publisher.
        int res = rmc_connect_tcp_by_address(ctx, &src_addr, &sock_ind);
        if (res)
            return res;

        sock = &ctx->sockets[sock_ind];
    }

    return _decode_multicast(ctx,
                             data,
                             payload_len,
                             &(sock->pubsub.publisher));
}

static int _process_cmd_packet(rmc_context_t* ctx, rmc_socket_t* sock, payload_len_t len)
{
    return 0;
}

static int _process_cmd_ack_single(rmc_context_t* ctx, rmc_socket_t* sock, payload_len_t len)
{
    cmd_ack_single_t ack;
    if (len < sizeof(ack))
        return EAGAIN;

    // If len is different than sizeof ack, drop it
    // and return a protocol error.
    if (len > sizeof(ack)) {
        circ_buf_free(&sock->read_buf, len, 0);
        return EPROTO;
    }
    
    circ_buf_read(&sock->read_buf, (uint8_t*) &ack, sizeof(ack), 0);
    pub_packet_ack(&sock->pubsub.subscriber, ack.packet_id);
    return 0;
}

static int _process_cmd_ack_interval(rmc_context_t* ctx, rmc_socket_t* sock, payload_len_t len)
{
    return 0;
}

// Return EAGAIN if we have a partial command that needs to more data
// to be processed.
// EAGAIN can be returned if one or more commands have been executed
// and it is the last command that is partial.
///
static int _process_tcp_read(rmc_context_t* ctx, rmc_poll_index_t p_ind)
{
    rmc_socket_t* sock = &ctx->sockets[p_ind];
    uint32_t in_use = circ_buf_in_use(&sock->read_buf);
    uint8_t command = 0;
    int res = 0;

    // Do we have a command byte?
    if (in_use < 1)
        return EAGAIN;

    // We have at least one byte available.
    res = circ_buf_read(&sock->read_buf, &command, 1, 0);

    if (res)
        return res;
    
    in_use -= 1;

    while(1) {
        switch(command) {
        case RMC_CMD_PACKET:
            if ((res = _process_cmd_packet(ctx, sock, in_use)) != 0)
                return res; // Most likely EAGAIN
            break;

        case RMC_CMD_ACK_SINGLE:
            if ((res = _process_cmd_ack_single(ctx, sock, in_use)) != 0)
                return res; // Most likely EAGAIN
            break;

        case RMC_CMD_ACK_INTERVAL:
            if ((res = _process_cmd_ack_interval(ctx, sock, in_use)) != 0)
                return res; // Most likely EAGAIN


        default:
            // FIXME: Disconnect subscriber and report issue.
            return EPROTO;
        }

        // Free the number of the bytes that cmd occupies.
        // _process_tcp_command() will have freed the number of bytes
        // taken up by whatever the command payload itself takes up,
        // leaving the first byte of the remaining data in use to be
        // the start of the next command.
        circ_buf_free(&sock->read_buf, 1, &in_use);

        in_use = circ_buf_in_use(&sock->read_buf);

        if (!in_use)
            return 0;

        // We are at the start of the next command.
        // Read the command byte.
        res = circ_buf_read(&sock->read_buf, &command, 1, 0);

        if (res)
            return res;
    }

    return 0;
}


int _tcp_read(rmc_context_t* ctx, rmc_poll_index_t p_ind)
{
    rmc_socket_t* sock = &ctx->sockets[p_ind];
    ssize_t res = 0;
    uint8_t *seg1 = 0;
    uint32_t seg1_len = 0;
    uint8_t *seg2 = 0;
    uint32_t seg2_len = 0;
    struct iovec iov[2];
    uint32_t available = circ_buf_available(&sock->read_buf);

    // Grab as much data as we can.
    // The call will only return available
    // data.
    circ_buf_alloc(&sock->read_buf,
                   available,
                   &seg1, &seg1_len,
                   &seg2, &seg2_len);

    if (!seg1_len) 
        return ENOMEM;

    // Setup a zero-copy scattered socket write
    iov[0].iov_base = seg1;
    iov[0].iov_len = seg1_len;
    iov[1].iov_base = seg2;
    iov[1].iov_len = seg2_len;
    
    res = readv(sock->poll_info.descriptor, iov, 2);

    if (res == -1)
        return errno;
    
    // Trim the tail end of the allocated data to match the number of
    // bytes read.
    circ_buf_trim(&sock->read_buf, res);

    return _process_tcp_read(ctx, p_ind);
    
}

int rmc_read(rmc_context_t* ctx, rmc_poll_index_t p_ind)
{
    int res = 0;

    if (!ctx)
        return EINVAL;

    if (p_ind == RMC_MULTICAST_RECV_INDEX) {
        res = _process_multicast_read(ctx);
    }

    if (p_ind == RMC_LISTEN_INDEX) {
        res = rmc_process_accept(ctx, &p_ind);
        return res;
    }

    // Is c_ind within our socket vector?
    if (p_ind >= RMC_MAX_SOCKETS)
        return EINVAL;

    if (ctx->sockets[p_ind].poll_info.descriptor == -1)
        return ENOTCONN;

    res = _tcp_read(ctx, p_ind);
    // Read poll is always active. Callback to re-arm.
    if (ctx->poll_modify) {
        rmc_poll_t pinfo = {
            .action = RMC_POLLREAD,
            .descriptor = ctx->sockets[p_ind].poll_info.descriptor,
            .rmc_index = p_ind
        };
        (*ctx->poll_modify)(ctx, &pinfo, &pinfo);
    }

    return res;
}


