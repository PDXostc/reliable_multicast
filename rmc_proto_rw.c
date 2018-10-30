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

#define RMC_MAX(x,y) ((x)>(y)?(x):(y))
#define RMC_MIN(x,y) ((x)<(y)?(x):(y))

static inline rmc_socket_t* _find_publisher_by_address(rmc_context_t* ctx,
                                                       struct sockaddr_in* addr)
{
    rmc_poll_index_t ind = 0;
    
    // FIXME: Replace with hash table search to speed up.
    while(ind <= ctx->max_socket_ind) {
        if (ctx->sockets[ind].descriptor != -1 &&
            !memcmp(&ctx->sockets[ind].remote_address, addr, sizeof(*addr)))
            return &ctx->sockets[ind];

        ++ind;
    }
}




// =============
// SOCKET READ
// =============
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
        packet += sizeof(pid);

        payload_len = *(payload_len_t*) packet;
        packet += sizeof(payload_len);
        len -= (payload_len + sizeof(pid) + sizeof(payload_len));

        // Check that we do not have a duploic
        if (sub_packet_is_duplicate(pub, pid))
            continue;

        // Use the provided memory allocator to reserve memory for
        // incoming payload.
        // Use malloc() if nothing is specified.
        if (ctx->payload_alloc)
            payload = (*ctx->payload_alloc)(payload_len);
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
    payload_len_t payload_len;
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    ssize_t res;
    int sock_ind = 0;
    rmc_socket_t* sock = 0;

    if (!ctx)
        return EINVAL;

    if (ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].descriptor == -1)
        return ENOTCONN;

    res = recvfrom(ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].descriptor,
                   buffer, sizeof(buffer),
                   MSG_DONTWAIT,
                   (struct sockaddr*) &src_addr, &addr_len);

    if (res == -1) {
        perror("rmc_proto::rmc_read_multicast(): recvfrom()");
        return errno;
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
    payload_len = *(payload_len_t*) buffer;

    return _decode_multicast(ctx,
                             buffer + sizeof(payload_len_t),
                             payload_len,
                             &sock->pubsub.publisher);
}


static int _process_cmd_packet(rmc_context_t* ctx, rmc_socket_t* sock, payload_len_t len)
{
    return 0;
}

static int _process_cmd_ack_single(rmc_context_t* ctx, rmc_socket_t* sock, payload_len_t len)
{
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
    uint32_t len = 0;
    int res;

    // Do we have any data to process
    if (!in_use)
        return 0;
            
    res = circ_buf_read(&sock->read_buf, &command, sizeof(command), &len);

    if (res)
        return res;

    // Did we get our precious byte?
    if (len == 0)
        return EAGAIN;

    
    in_use -= sizeof(command);

    while(1) {
        switch(command) {
        case RMC_CMD_PACKET:
            if ((res = _process_cmd_packet(ctx, sock, len)) != 0)
                return res; // Most likely EAGAIN
            break;

        case RMC_CMD_ACK_SINGLE:
            if ((res = _process_cmd_ack_single(ctx, sock, len)) != 0)
                return res; // Most likely EAGAIN
            break;

        case RMC_CMD_ACK_INTERVAL:
            if ((res = _process_cmd_ack_interval(ctx, sock, len)) != 0)
                return res; // Most likely EAGAIN


        default:
            // FIXME: Disconnect subscriber and report issue.
            abort();
        }

        // Free the number of the bytes that cmd occupies.
        // _process_tcp_command() will have freed the number of bytes
        // taken up by whatever the command payload itself takes up,
        // leaving the first byte of the remaining data in use to be
        // the start of the next command.
        circ_buf_free(&sock->read_buf, sizeof(command), &in_use);

        res = circ_buf_read(&sock->read_buf, &command, 1, &len);

        if (res)
            return res;

        // If we didn't get our precious byte, it means that we
        // executed all commands, and there is no partial command
        // left to run.
        
        if (len == 0)
            return 0;
    }

    return 0;
}


int rmc_read(rmc_context_t* ctx, rmc_poll_index_t p_ind)
{
    int res = 0;
    if (!ctx)
        return EINVAL;

    if (p_ind == RMC_MULTICAST_SOCKET_INDEX) {
        res = _process_multicast_read(ctx);
    }

    if (p_ind == RMC_LISTEN_SOCKET_INDEX) {
        res = rmc_process_accept(ctx, &p_ind);
        return res;
    }

    // Is c_ind within our socket vector?
    if (p_ind < 2 || p_ind >= RMC_MAX_SOCKETS)
        return EINVAL;

    if (ctx->sockets[p_ind].descriptor == -1)
        return ENOTCONN;

    res = _process_tcp_read(ctx, p_ind);
    // Read poll is always active. Callback to re-arm.
    if (ctx->poll_modify)
        (*ctx->poll_modify)(&ctx->sockets[p_ind].poll_info,
                            &ctx->sockets[p_ind].poll_info);

    return res;
}


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
    iov[1].iov_base = seg1;
    iov[1].iov_len = seg1_len;
    iov[2].iov_base = seg2;
    iov[2].iov_len = seg2_len;

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


