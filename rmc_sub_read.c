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



static int _decode_multicast(rmc_sub_context_t* ctx,
                             uint8_t* packet,
                             ssize_t packet_len,
                             rmc_connection_t* conn)
{
    payload_len_t len = (payload_len_t) packet_len;
    uint8_t* payload = 0;
    sub_publisher_t* pub = &ctx->publishers[conn->connection_index];

    usec_timestamp_t now = rmc_usec_monotonic_timestamp();

    // Traverse the received datagram and extract all packets
    while(len) {
        cmd_packet_header_t* cmd_pack = (cmd_packet_header_t*) packet;

        //      printf("_decode_multicast(): Len[%d] Hdr Len[%lu] Payload Len[%d] Payload[%s]\n",
//               len, sizeof(cmd_packet_header_t), cmd_pack->payload_len, packet + sizeof(cmd_packet_header_t));

        // Check that we do not have a duplicate
        if (sub_packet_is_duplicate(pub, cmd_pack->pid)) {
            printf("_decode_multicast(%lu): Duplicate or pre-connect straggler\n",
                   cmd_pack->pid);
            packet += sizeof(cmd_packet_header_t) + cmd_pack->payload_len;
            len -= sizeof(cmd_packet_header_t) + cmd_pack->payload_len;
            continue;
        }

        // Use the provided memory allocator to reserve memory for
        // incoming payload.
        // Use malloc() if nothing is specified.
        // Must be freed by rmc_packet_dispatched()
        if (ctx->payload_alloc)
            payload = (*ctx->payload_alloc)(cmd_pack->payload_len, ctx->user_data);
        else
            payload = malloc(cmd_pack->payload_len);
 
        if (!payload)
            return ENOMEM;

        packet += sizeof(cmd_packet_header_t);
        memcpy(payload, packet, cmd_pack->payload_len);
        packet += cmd_pack->payload_len;
        len -= sizeof(cmd_packet_header_t) + cmd_pack->payload_len;

        sub_packet_received(pub,
                            cmd_pack->pid,payload, cmd_pack->payload_len,
                            now, user_data_ptr(conn));
    }

    // Process received packages, moving consectutive ones
    // over to the ready queue.
    sub_process_received_packets(pub);
    return 0;
}


static int _process_multicast_read(rmc_sub_context_t* ctx, uint8_t* read_res)
{
    uint8_t buffer[RMC_MAX_PAYLOAD];
    uint8_t *data = buffer;
    char src_addr_str[80];
    char listen_addr_str[80];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    ssize_t len = 0;
    int res = 0;
    int sock_ind = 0;
    rmc_connection_t* conn = 0;
    multicast_header_t* mcast_hdr = (multicast_header_t*) data;

    if (read_res)
        *read_res = RMC_ERROR;

    if (!ctx)
        return EINVAL;

    if (ctx->mcast_recv_descriptor == -1)
        return ENOTCONN;

    len = recvfrom(ctx->mcast_recv_descriptor,
                   buffer, sizeof(buffer),
                   0,
                   (struct sockaddr*) &src_addr, &addr_len);

    if (len == -1) {
        perror("rmc_proto::rmc_read_multicast(): recvfrom()");
        return errno;
    }

    if (len < sizeof(multicast_header_t)) {
        fprintf(stderr, "Corrupt header. Needed [%lu] header bytes. Got %lu\n",
                sizeof(multicast_header_t), len);
        return EPROTO;
    }
                
    if (len < sizeof(multicast_header_t) + mcast_hdr->payload_len) {
        fprintf(stderr, "Corrupt packet. Needed [%lu] header + payload bytes. Got %lu\n",
                sizeof(multicast_header_t) + mcast_hdr->payload_len, len);
        return EPROTO;
    }
        
    strcpy(src_addr_str, inet_ntoa(src_addr.sin_addr));
    strcpy(listen_addr_str, inet_ntoa( (struct in_addr) { .s_addr = htonl(mcast_hdr->listen_ip) }));
    printf("mcast_rx(): len[%.5d] from[%s:%d] listen[%s:%d]",
           mcast_hdr->payload_len,
           src_addr_str, ntohs(src_addr.sin_port),
           listen_addr_str, mcast_hdr->listen_port);
           

    data += sizeof(multicast_header_t);
    
    // FIXME: REMOVE WHEN WE HAVE DELETED IP_MULTICAST_LOOP
    if (mcast_hdr->context_id == ctx->context_id) {
        puts(" - loopback (skipped)");
        if (ctx->conn_vec.poll_modify)
            (*ctx->conn_vec.poll_modify)(ctx->user_data,
                                         ctx->mcast_recv_descriptor,
                                         RMC_MULTICAST_RECV_INDEX,
                                         RMC_POLLREAD,
                                         RMC_POLLREAD);
        *read_res = RMC_READ_MULTICAST_LOOPBACK;
        return 0; // Loopback message
    }
    putchar('\n');

    // If we have a complete spec for the networ address in the packet header, use that.
    // If listen_ip_addr is 0, then use the IP address provided in source address returned
    // by recvfrom
    //
    if (!mcast_hdr->listen_ip)
        mcast_hdr->listen_ip = ntohl(src_addr.sin_addr.s_addr);

    // Find the socket we use to ack received packets back to the publisher.
    conn = _rmc_conn_find_by_address(&ctx->conn_vec, mcast_hdr->listen_ip, mcast_hdr->listen_port);

    // If no socket is setup, initiate the connection to the publisher.
    // Drop the recived packet
    if (!conn) {
        // Add an outbound tcp connection to the publisher.
        res = _rmc_conn_connect_tcp_by_address(&ctx->conn_vec, mcast_hdr->listen_ip, mcast_hdr->listen_port, &sock_ind);
        

        if (read_res) {
            if (res)
                *read_res = RMC_ERROR;
            else
                *read_res = RMC_READ_MULTICAST_NOT_READY;
        }
        goto rearm;
    }

    // Drop the packet if we are still setting up the packet
    if (conn->mode == RMC_CONNECTION_MODE_CONNECTING) {
        res = 0;
        if (read_res)
            *read_res = RMC_READ_MULTICAST_NOT_READY;
        goto rearm;
    }

    // We have a valid ack socket back to the server.
    // Processs the packet

    if (read_res)
        *read_res = RMC_READ_MULTICAST;
    
    // Record if we have any packets ready to ack prior
    // to decoding additional packets.
    res = _decode_multicast(ctx, data, mcast_hdr->payload_len, conn);
        

rearm:
    // Re-arm the poll descriptor and return.
    if (ctx->conn_vec.poll_modify)
        (*ctx->conn_vec.poll_modify)(ctx->user_data,
                                     ctx->mcast_recv_descriptor,
                                     RMC_MULTICAST_RECV_INDEX,
                                     RMC_POLLREAD,
                                     RMC_POLLREAD);

    
    return res;
}

static int _process_cmd_packet(rmc_sub_context_t* ctx, rmc_connection_t* conn, payload_len_t len)
{
    return 0;
}

// Return EAGAIN if we have a partial command that needs to more data
// to be processed.
// EAGAIN can be returned if one or more commands have been executed
// and it is the last command that is partial.
///
static int _process_tcp_read(rmc_sub_context_t* ctx,
                             rmc_connection_index_t s_ind,
                             uint8_t* read_res)
{
    rmc_connection_t* conn = _rmc_conn_find_by_index(&ctx->conn_vec, s_ind);
    uint32_t in_use = circ_buf_in_use(&conn->read_buf);
    uint8_t command = 0;
    int sock_err = 0;
    socklen_t len = sizeof(sock_err);
    int res;

    assert(conn);
    // Do we have a command byte?
    if (in_use < 1) {
        if (getsockopt(conn->descriptor,
                       SOL_SOCKET,
                       SO_ERROR,
                       &sock_err,
                       &len) == -1) {
            printf("process_tcp_read(): getsockopt(): %s\n",
                   strerror(errno));
            sock_err = errno; // Save it.
            _rmc_conn_close_connection(&ctx->conn_vec, conn->connection_index);
            return sock_err;
        }
        printf("process_tcp_read(): getsockopt(ok): %s\n",
               strerror(sock_err));
        return sock_err;
    }


    // We have at least one byte available.
    res = circ_buf_read(&conn->read_buf, &command, 1, 0);
    circ_buf_free(&conn->read_buf, 1, &in_use);

    if (res) {
        if (read_res)
            *read_res = RMC_ERROR;
        return res;
    }
    
    if (read_res)
        *read_res = RMC_READ_TCP;
    

    while(1) {
        switch(command) {
        case RMC_CMD_PACKET:
            if ((res = _process_cmd_packet(ctx, conn, in_use)) == EAGAIN) {
                return 0;
            }
            break;


        default:
            // FIXME: Disconnect subscriber and report issue.
            return EPROTO;
        }

        in_use = circ_buf_in_use(&conn->read_buf);

        if (!in_use)
            return 0;

        // We are at the start of the next command.
        // Read the command byte.
        res = circ_buf_read(&conn->read_buf, &command, 1, 0);
        if (res)
            return res;

        circ_buf_free(&conn->read_buf, 1, 0);
    }

    return 0;
}


static int _tcp_read(rmc_sub_context_t* ctx, rmc_connection_index_t s_ind, uint8_t* read_res)
{
    rmc_connection_t* conn = _rmc_conn_find_by_index(&ctx->conn_vec, s_ind);
    ssize_t res = 0;
    uint8_t *seg1 = 0;
    uint32_t seg1_len = 0;
    uint8_t *seg2 = 0;
    uint32_t seg2_len = 0;
    struct iovec iov[2];
    uint32_t available = circ_buf_available(&conn->read_buf);

    // Grab as much data as we can.
    // The call will only return available
    // data.
    circ_buf_alloc(&conn->read_buf,
                   available,
                   &seg1, &seg1_len,
                   &seg2, &seg2_len);

    if (!seg1_len) {
        if (read_res)
            *read_res = RMC_ERROR;
        return ENOMEM;
    }

    // Setup a zero-copy scattered socket write
    iov[0].iov_base = seg1;
    iov[0].iov_len = seg1_len;
    iov[1].iov_base = seg2;
    iov[1].iov_len = seg2_len;
    
    res = readv(conn->descriptor, iov, 2);


    if (res == -1 || res == 0) {
        if (read_res)
            *read_res = RMC_READ_DISCONNECT;

        // Give back the memory.
        circ_buf_trim(&conn->read_buf, available);
        return EPIPE;
    }
    
    // Trim the tail end of the allocated data to match the number of
    // bytes read.
    printf("circ_buf_alloc(): Got %d. Trimming to %ld\n", available, res);
    circ_buf_trim(&conn->read_buf, res);

    return _process_tcp_read(ctx, s_ind, read_res);
    
}

int rmc_sub_read(rmc_sub_context_t* ctx, rmc_connection_index_t s_ind, uint8_t* op_res)
{
    int res = 0;
    rmc_connection_t* conn = 0;

    if (!ctx)
        return EINVAL;

    conn = _rmc_conn_find_by_index(&ctx->conn_vec, s_ind);

    if (!conn) {
        if (op_res) 
            *op_res = RMC_ERROR;

        return ENOTCONN;
    }
    
    if (s_ind == RMC_MULTICAST_RECV_INDEX) 
        return _process_multicast_read(ctx, op_res);
            
            

    res = _tcp_read(ctx, s_ind, op_res);

    if (res == EPIPE) {
        _rmc_conn_close_connection(&ctx->conn_vec, s_ind);
        return 0; // This is not an error, just regular maintenance.
    }

    // Read poll is always active. Callback to re-arm.
    if (ctx->conn_vec.poll_modify) {
        (*ctx->conn_vec.poll_modify)(ctx->user_data, 
                                     conn->descriptor, 
                                     s_ind, 
                                     RMC_POLLREAD, 
                                     RMC_POLLREAD);
    }
    return res;
}

