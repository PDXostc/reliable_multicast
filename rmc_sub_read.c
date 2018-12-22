// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "reliable_multicast.h"
#include "rmc_log.h"
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

static int decode_unsubscribed_multicast(rmc_sub_context_t* ctx,
                                         packet_header_t* pack_hdr,
                                         uint8_t* payload)
{
    int sock_ind = 0;
    int res = 1;

    if (pack_hdr->pid) {
        RMC_LOG_COMMENT("Len[%d] Pid[%lu] - Ignoring data packet since we are not yet subscribed",
                        pack_hdr->payload_len,
                        pack_hdr->pid);

        return 0;
    }
        
            
    RMC_LOG_COMMENT("Len[%d] Pid[%lu] - Announce!",
                    pack_hdr->payload_len,
                    pack_hdr->pid);
            
    // Add an outbound tcp connection to the publisher.
        
    // If set, invoke callback and determine if we are to setup subscription to
    // publisher.
    if (ctx->announce_cb) {
        char listen_ip_str[128];
        strcpy(listen_ip_str, inet_ntoa( (struct in_addr) { .s_addr = htonl(pack_hdr->listen_ip) }));

        res = (*ctx->announce_cb)(ctx, listen_ip_str, pack_hdr->listen_port, payload, pack_hdr->payload_len);
    }

    if (res)
        rmc_conn_connect_tcp_by_address(&ctx->conn_vec, pack_hdr->listen_ip, pack_hdr->listen_port, &sock_ind);
        
    return 0;
}


static int decode_subscribed_multicast(rmc_sub_context_t* ctx,
                                       rmc_connection_t* conn,
                                       packet_header_t* pack_hdr,
                                       uint8_t* payload)

{
    sub_publisher_t* pub = &ctx->publishers[conn->connection_index];
    usec_timestamp_t now = rmc_usec_monotonic_timestamp();
    usec_timestamp_t pack_rec_time = 0;
    usec_timestamp_t start = 0;
    uint8_t* payload_copy = 0;

    // Skip announce packets.
    if (!pack_hdr->pid) {
        RMC_LOG_COMMENT("Already subscribing - Ignoring announce");
        return 0;
    }

    // Check that we do not have a duplicate
    if (sub_packet_is_duplicate(pub, pack_hdr->pid)) {
        RMC_LOG_DEBUG("pid %lu  is duplicate or pre-connect straggler",
                      pack_hdr->pid);
        return 0;
    }


    RMC_LOG_DEBUG("Len[%d] Pid[%lu]", pack_hdr->payload_len, pack_hdr->pid);

    // Use the provided memory allocator to reserve memory for
    // incoming payload.
    // Use malloc() if nothing is specified.
    // Must be freed by rmc_packet_dispatched()
    //
    // FIXME: If we allocate payload in multicast_read()
    //        We can omot the memcpy below.
    ///    
    if (ctx->payload_alloc)
        payload_copy = (*ctx->payload_alloc)(pack_hdr->payload_len, ctx->user_data);
    else
        payload_copy = malloc(pack_hdr->payload_len);
    
    if (!payload_copy) {
        RMC_LOG_FATAL("malloc(%d): %s", pack_hdr->payload_len, strerror(errno));
        exit(255);
    }

    memcpy(payload_copy, payload, pack_hdr->payload_len);

    start = rmc_usec_monotonic_timestamp();
    rmc_sub_packet_received(ctx,
                            conn->connection_index,
                            pack_hdr->pid,
                            payload_copy, pack_hdr->payload_len,
                            now, user_data_u32(conn->connection_index));

    pack_rec_time += rmc_usec_monotonic_timestamp() - start;

    // Process received packages, moving consectutive ones
    // over to the ready queue.

    sub_process_received_packets(pub, &ctx->dispatch_ready);

    RMC_LOG_COMMENT("Received multicast pid: %lu", pack_hdr->pid);

    return 0;
}


static int process_multicast_read(rmc_sub_context_t* ctx, uint8_t* read_res, uint32_t src_addr, uint8_t* buffer, int len)
{
    uint8_t *data = buffer;
    int res = 0;
    rmc_connection_t* conn = 0;
    packet_header_t* pack_hdr = (packet_header_t*) data;

    if (len < sizeof(packet_header_t)) {
        RMC_LOG_ERROR("Corrupt header. Needed [%lu] header bytes. Got [%lu]\n",
                      sizeof(packet_header_t), len);
        return EPROTO;
    }
                
    if (len < sizeof(packet_header_t) + pack_hdr->payload_len) {
        RMC_LOG_ERROR("Corrupt packet. Needed [%lu + %d = %lu] header + payload bytes. Got %lu\n",
                sizeof(packet_header_t),
                pack_hdr->payload_len, 
                sizeof(packet_header_t) + pack_hdr->payload_len, len);

        return EPROTO;
    }

    // If the publisher has a listen socket that is bound on all
    // interfaces (IF_ANY), we will see 0.0.0.0 as the
    // pack_hdr->listen_ip. In these cases substitute this address
    // with the source address that the multicast packet came from.
    if (pack_hdr->listen_ip == 0)
        pack_hdr->listen_ip = src_addr;

    data += sizeof(packet_header_t);
    
    // Find the socket we use to ack received packets back to the publisher.
    conn = rmc_conn_find_by_address(&ctx->conn_vec, pack_hdr->listen_ip, pack_hdr->listen_port);

    // If no socket is setup, initiate the connection to the publisher.
    // Drop the recived packet

    if (!conn || conn->mode == RMC_CONNECTION_MODE_CONNECTING) {
        res = decode_unsubscribed_multicast(ctx,
                                            pack_hdr,
                                            data);

        if (read_res)
            *read_res = RMC_READ_MULTICAST_NOT_READY;

        return res;
    }


    // We have a valid ack socket back to the server.
    // Processs the packet

    if (read_res)
        *read_res = RMC_READ_MULTICAST;
    
    // Record if we have any packets ready to ack prior
    // to decoding additional packets.

    res =  decode_subscribed_multicast(ctx, conn, pack_hdr, data);

    return res;
}


static int multicast_read(rmc_sub_context_t* ctx, uint8_t* read_res)
{
    uint8_t buffer[RMC_MAX_PACKET];
    char src_addr_str[80];
    char listen_addr_str[80];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    ssize_t len = 0;
    int res = 0;

    if (read_res)
        *read_res = RMC_ERROR;

    if (!ctx)
        return EINVAL;

    if (ctx->mcast_recv_descriptor == -1) 
        return ENOTCONN;


    while(!res) {
        len = recvfrom(ctx->mcast_recv_descriptor,
                       buffer, sizeof(buffer),
                       MSG_DONTWAIT,
                       (struct sockaddr*) &src_addr, &addr_len);

        if (len == 0 || (len == -1 && errno == EAGAIN)) {
            res = EAGAIN;
            goto rearm;
        }

        if (len == -1 ) {
            RMC_LOG_WARNING("recvfrom(): %d: %s ", errno, strerror(errno));
            res = errno;
            goto rearm;
        }
           
        res = process_multicast_read(ctx, read_res, ntohl(src_addr.sin_addr.s_addr), buffer, len);
    }

rearm:
    // Re-arm the poll descriptor and return.
    if (ctx->conn_vec.poll_modify)
        (*ctx->conn_vec.poll_modify)(ctx->user_data,
                                     ctx->mcast_recv_descriptor,
                                     RMC_MULTICAST_INDEX,
                                     RMC_POLLREAD,
                                     RMC_POLLREAD);

    
    return res;
}

static int process_cmd_packet(rmc_connection_t* conn, user_data_t user_data)
{
    uint8_t *payload = 0;
    packet_header_t pack_hdr;
    rmc_sub_context_t* ctx = (rmc_sub_context_t*) user_data.ptr;
    usec_timestamp_t current_ts = rmc_usec_monotonic_timestamp();

    // Make sure that we have enough data for the header.
    // Please note that the command byte is still lingering as the
    // first byte in conn->read_buf since we cannot free it until we
    // have atomically processed or rejeceted the command.
    //
    if (circ_buf_in_use(&conn->read_buf) < 1 + sizeof(packet_header_t)) {
        RMC_LOG_COMMENT("Incomplete header data. Want [%lu] Got[%d]",
               1 + sizeof(packet_header_t), circ_buf_in_use(&conn->read_buf));

        // Don't free any memory since we will get called again when we have more data.
        return EAGAIN;
    }

    // Read the command byte and the packet header
    circ_buf_read_offset(&conn->read_buf, 1, (uint8_t*) &pack_hdr, sizeof(pack_hdr), 0);

    // Now we know how big the payload is. Check if we have enough memory for an atomic
    // process or reject.
    if (circ_buf_in_use(&conn->read_buf) < 1 + sizeof(packet_header_t) + pack_hdr.payload_len) {
        RMC_LOG_COMMENT("Incomplete payload data. Want [%d] Got[%d]",
                        1 + sizeof(packet_header_t) + pack_hdr.payload_len, circ_buf_in_use(&conn->read_buf));

        // Don't free any memory since we will get called again when we have more data.
        return EAGAIN;
    }

    // We have enough data to process the entire packet
    // Free command byte and packet header from read buffer.
    circ_buf_free(&conn->read_buf, 1 + sizeof(packet_header_t), 0);

    // Is the packet a duplicate?
    if (sub_packet_is_duplicate(&ctx->publishers[conn->connection_index], pack_hdr.pid)) {
        RMC_LOG_DEBUG("Duplicate: %lu", pack_hdr.pid);

        // Free payload
        circ_buf_free(&conn->read_buf, pack_hdr.payload_len, 0);
        return 0; // Dups are ok.
    }

    // Allocate memory for payload
    if (ctx->payload_alloc)
        payload = (*ctx->payload_alloc)(pack_hdr.payload_len, ctx->user_data);
    else
        payload = malloc(pack_hdr.payload_len);

    if (!payload) {
        RMC_LOG_FATAL("memory allocation failed");
        exit(255);
    }


    // Read in payload and free it from conn->read_buf
    circ_buf_read(&conn->read_buf, payload, pack_hdr.payload_len, 0);
    circ_buf_free(&conn->read_buf, pack_hdr.payload_len, 0);

    RMC_LOG_COMMENT("Received resend pid: %lu", pack_hdr.pid);
    
    // Since we are getting this via TCP command channel,
    // we do not need to ack it.
    //
    // Call sub_packet_received() directly instead of
    // rmc_sub_packet_received() since rmc_sub_packet_received() will
    // setup the packet for acknowledgement before calling
    // sub_packet_received().
    //
    sub_packet_received(&ctx->publishers[conn->connection_index],
                        pack_hdr.pid,
                        payload, pack_hdr.payload_len,
                        rmc_usec_monotonic_timestamp(),
                        user_data_u32(conn->connection_index));

    return 0;
}



int rmc_sub_close_connection(rmc_sub_context_t* ctx, rmc_index_t s_ind)
{
    RMC_LOG_COMMENT("index[%d]", s_ind);

    rmc_conn_close_connection(&ctx->conn_vec, s_ind);

    sub_reset_publisher(&ctx->publishers[s_ind],
                         lambda(void, (void* payload, payload_len_t payload_len, user_data_t user_data) {
                                 if (ctx->payload_free)
                                     (*ctx->payload_free)(payload, payload_len, user_data);
                                 else
                                     free(payload);
                             }));
    return 0;
}


int rmc_sub_read(rmc_sub_context_t* ctx, rmc_index_t s_ind, uint8_t* op_res)
{
    int res = 0;
    uint8_t dummy_res = 0;
    rmc_connection_t* conn = 0;
    static rmc_conn_command_dispatch_t dispatch_table[] = {
        { .command = RMC_CMD_PACKET, .dispatch = process_cmd_packet },
        { .command = 0, .dispatch = 0 }
    };

    if (!ctx)
        return EINVAL;

    if (!op_res)
        op_res = &dummy_res;

    // Is this a multicast pacekt?
    if (s_ind == RMC_MULTICAST_INDEX) {
        do { 
            res = multicast_read(ctx, op_res);
        } while(!res);

        return (res == EAGAIN)?0:res;
    }


    // This is incoming data on tcp. 

    // Find connection.
    conn = rmc_conn_find_by_index(&ctx->conn_vec, s_ind);

    // No conn?
    if (!conn || conn->mode != RMC_CONNECTION_MODE_CONNECTED) {
        *op_res = RMC_ERROR;
        return ENOTCONN;
    }

    // Read data from publisher.
    res = rmc_conn_tcp_read(&ctx->conn_vec, s_ind, op_res,
                             dispatch_table, user_data_ptr(ctx));

    if (res == ENOMEM) {
        RMC_LOG_WARNING("Cannot read tcp control channel for index [%d] since buffer is full.");
        return ENOMEM;
    }
        
    // Are we disconnected?
    if (res == EPIPE) {
        *op_res = RMC_READ_DISCONNECT;
        RMC_LOG_COMMENT("Index %d got disconnected", s_ind);
        rmc_sub_close_connection(ctx, s_ind);
        return 0; // This is not an error, just regular disconnect.
    }

    // Process packets (which may be none in case of error)
    sub_process_received_packets(&ctx->publishers[s_ind], &ctx->dispatch_ready);

    // Did rmc_conn_tcp_read error out?
    if (res == EPROTO) {
        *op_res = RMC_ERROR;
        rmc_sub_close_connection(ctx, s_ind);
        return res;
    }
        
    *op_res = RMC_READ_TCP;

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

