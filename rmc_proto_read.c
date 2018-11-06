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

static inline rmc_connection_t* _find_publisher_by_address(rmc_context_t* ctx,
                                                       uint32_t address,
                                                       uint16_t port)
{
    rmc_connection_index_t ind = 0;

    // Do we have any connections in use at all?
    if (ctx->max_connection_ind == -1)
        return 0;
    
    // FIXME: Replace with hash table search to speed up.
    while(ind < ctx->max_connection_ind) {
        if (ctx->connections[ind].descriptor != -1 &&
            address == ctx->connections[ind].remote_address &&
            port == ctx->connections[ind].remote_port)
            return &ctx->connections[ind];

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
    uint8_t* payload = 0;
    // Traverse the received datagram and extract all packets
    while(len) {
        cmd_packet_header_t* cmd_pack = (cmd_packet_header_t*) packet;

        // Check that we do not have a duplicate
        if (sub_packet_is_duplicate(pub, cmd_pack->pid))
            continue;

        // Use the provided memory allocator to reserve memory for
        // incoming payload.
        // Use malloc() if nothing is specified.
        if (ctx->payload_alloc)
            payload = (*ctx->payload_alloc)(ctx, cmd_pack->payload_len);
        else
            payload = malloc(cmd_pack->payload_len);

        if (!payload)
            return ENOMEM;

        packet += sizeof(cmd_packet_header_t);
        memcpy(payload, packet, cmd_pack->payload_len);
        packet += cmd_pack->payload_len;
        len -= sizeof(cmd_packet_header_t) + cmd_pack->payload_len;

        sub_packet_received(pub, cmd_pack->pid, payload, cmd_pack->payload_len);
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
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    ssize_t res;
    int sock_ind = 0;
    rmc_connection_t* sock = 0;
    multicast_header_t* mcast_hdr = (multicast_header_t*) data;

    if (!ctx)
        return EINVAL;

    if (ctx->mcast_recv_descriptor == -1)
        return ENOTCONN;

    res = recvfrom(ctx->mcast_recv_descriptor,
                   buffer, sizeof(buffer),
                   0,
                   (struct sockaddr*) &src_addr, &addr_len);

    if (res == -1) {
        perror("  rmc_proto::rmc_read_multicast(): recvfrom()");
        return errno;
    }

    if (res < sizeof(multicast_header_t)) {
        fprintf(stderr, "  Corrupt header. Needed [%lu] header bytes. Got %lu\n",
                sizeof(multicast_header_t), res);
        return EPROTO;
    }
                
    if (res < sizeof(multicast_header_t) + mcast_hdr->payload_len) {
        fprintf(stderr, "  Corrupt packet. Needed [%lu] header + payload bytes. Got %lu\n",
                sizeof(multicast_header_t) + mcast_hdr->payload_len, res);
        return EPROTO;
    }
        
    printf("  mcast_rx(): ctx_id[0x%.8X] len[%.5d] from[%s:%d] listen[%s:%d]",
           mcast_hdr->context_id,
           mcast_hdr->payload_len,
           inet_ntoa(src_addr.sin_addr), ntohs(src_addr.sin_port),
           inet_ntoa( (struct in_addr) { .s_addr = htonl(mcast_hdr->listen_ip) }) , mcast_hdr->listen_port),
           

    data += sizeof(multicast_header_t);
    
    // FIXME: REMOVE WHEN WE HAVE DELETED IP_MULTICAST_LOOP
    if (mcast_hdr->context_id == ctx->context_id) {
        puts(" - loopback (skipped)");
        if (ctx->poll_modify)
            (*ctx->poll_modify)(ctx,
                                ctx->mcast_recv_descriptor,
                                RMC_MULTICAST_RECV_INDEX,
                                RMC_POLLREAD,
                                RMC_POLLREAD);
        return ELOOP; // Loopback message
    }
    putchar('\n');

    // If we have a complete spec for the networ address in the packet header, use that.
    // If listen_ip_addr is 0, then use the IP address provided in source address returned
    // by recvfrom

    if (!mcast_hdr->listen_ip)
        mcast_hdr->listen_ip = ntohl(src_addr.sin_addr.s_addr);

    sock = _find_publisher_by_address(ctx, mcast_hdr->listen_ip, mcast_hdr->listen_port);

    // No publisher found?
    if (!sock) {
        // Add an outbound tcp connection to the publisher.
        int res = 0;
        res = rmc_connect_tcp_by_address(ctx, mcast_hdr->listen_ip, mcast_hdr->listen_port, &sock_ind);
        if (res)
            return res;

        sock = &ctx->connections[sock_ind];
    }

    return _decode_multicast(ctx,
                             data,
                             mcast_hdr->payload_len,
                             &(sock->pubsub.publisher));
}

static int _process_cmd_packet(rmc_context_t* ctx, rmc_connection_t* sock, payload_len_t len)
{
    return 0;
}

static int _process_cmd_ack_single(rmc_context_t* ctx, rmc_connection_t* sock, payload_len_t len)
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

static int _process_cmd_ack_interval(rmc_context_t* ctx, rmc_connection_t* sock, payload_len_t len)
{
    return 0;
}

// Return EAGAIN if we have a partial command that needs to more data
// to be processed.
// EAGAIN can be returned if one or more commands have been executed
// and it is the last command that is partial.
///
static int _process_tcp_read(rmc_context_t* ctx, rmc_connection_index_t s_ind)
{
    rmc_connection_t* sock = &ctx->connections[s_ind];
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


int _tcp_read(rmc_context_t* ctx, rmc_connection_index_t s_ind)
{
    rmc_connection_t* sock = &ctx->connections[s_ind];
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
    
    res = readv(sock->descriptor, iov, 2);

    if (res == -1)
        return errno;
    
    // Trim the tail end of the allocated data to match the number of
    // bytes read.
    circ_buf_trim(&sock->read_buf, res);

    return _process_tcp_read(ctx, s_ind);
    
}

int rmc_read(rmc_context_t* ctx, rmc_connection_index_t s_ind)
{
    int res = 0;

    if (!ctx)
        return EINVAL;

    if (s_ind == RMC_MULTICAST_RECV_INDEX) 
        return _process_multicast_read(ctx);


    if (s_ind == RMC_LISTEN_INDEX) 
        return rmc_process_accept(ctx, &s_ind);


    // Is c_ind within our connection vector?
    if (s_ind >= RMC_MAX_CONNECTIONS)
        return EINVAL;

    if (ctx->connections[s_ind].descriptor == -1)
        return ENOTCONN;

    res = _tcp_read(ctx, s_ind);
    // Read poll is always active. Callback to re-arm.
    if (ctx->poll_modify) {
        (*ctx->poll_modify)(ctx, 
                            ctx->connections[s_ind].descriptor, 
                            s_ind, 
                            RMC_POLLREAD, 
                            RMC_POLLREAD);
    }
    return res;
}


