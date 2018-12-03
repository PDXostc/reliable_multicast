// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "reliable_multicast.h"
#include <string.h>
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

static int _decode_unsubscribed_multicast(rmc_sub_context_t* ctx,
                                          rmc_connection_t* conn,
                                          uint8_t* packet,
                                          ssize_t packet_len,
                                          uint32_t listen_ip,
                                          uint16_t listen_port)
{
    payload_len_t len = (payload_len_t) packet_len;

    // Traverse the received datagram and extract all packets
    while(len) {
        cmd_packet_header_t* cmd_pack = (cmd_packet_header_t*) packet;
        int sock_ind = 0;
        int res = 1;

        packet += sizeof(cmd_packet_header_t);

        if (cmd_pack->pid) {
            printf("_decode_unsubscribed_multicast(): Len[%d] Hdr Len[%lu] Pid[%lu], Payload Len[%d] Payload[%s] - Ignored.\n",
                   len, sizeof(cmd_packet_header_t), cmd_pack->pid, cmd_pack->payload_len, packet);

            goto dump_payload;
        }
        
        // If conn is set, then it will always be RMC_CONNECTION_MODE_CONNECTING
        // In that case, just dump the packet and continue.
        if (conn) {
            printf("_decode_unsubscribed_multicast(): Len[%d] Hdr Len[%lu] Payload Len[%d] Payload[%s] - Announce: connection already in progress\n",
                   len, sizeof(cmd_packet_header_t), cmd_pack->payload_len, packet);
            goto dump_payload;
        }
            
        printf("_decode_unsubscribed_multicast(): Len[%d] Hdr Len[%lu] Pid[%lu], Payload Len[%d] Payload[%s] - Announce!\n",
               len, sizeof(cmd_packet_header_t), cmd_pack->pid, cmd_pack->payload_len, packet);
            
        // Add an outbound tcp connection to the publisher.
        
        // If set, invoke callback and determine if we are to setup subscription to
        // publisher.
        if (ctx->announce_cb) {
            char listen_ip_str[128];
            strcpy(listen_ip_str, inet_ntoa( (struct in_addr) { .s_addr = htonl(listen_ip) }));

            res = (*ctx->announce_cb)(ctx, listen_ip_str, listen_port, packet, cmd_pack->payload_len);
        }

        if (res)
            rmc_conn_connect_tcp_by_address(&ctx->conn_vec, listen_ip, listen_port, &sock_ind);
        
dump_payload:
        packet += cmd_pack->payload_len;
        len -= sizeof(cmd_packet_header_t) + cmd_pack->payload_len;
    }
}


static int _decode_subscribed_multicast(rmc_sub_context_t* ctx,
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


        // Skip announce packets.
        if (!cmd_pack->pid) {
            printf("_decode_multicast(): Ignoring announce\n");
            packet += sizeof(cmd_packet_header_t) + cmd_pack->payload_len;
            len -= sizeof(cmd_packet_header_t) + cmd_pack->payload_len;
            continue;
        }

        // Check that we do not have a duplicate
        if (sub_packet_is_duplicate(pub, cmd_pack->pid)) {
            printf("_decode_multicast(%lu): Duplicate or pre-connect straggler\n",
                   cmd_pack->pid);
            packet += sizeof(cmd_packet_header_t) + cmd_pack->payload_len;
            len -= sizeof(cmd_packet_header_t) + cmd_pack->payload_len;
            continue;
        }


        printf("_decode_subscribed_multicast(): Len[%d] Hdr Len[%lu] Pid[%lu], Payload Len[%d] Payload[%s]\n",
               len, sizeof(cmd_packet_header_t), cmd_pack->pid, cmd_pack->payload_len, packet + sizeof(cmd_packet_header_t));

        // Use the provided memory allocator to reserve memory for
        // incoming payload.
        // Use malloc() if nothing is specified.
        // Must be freed by rmc_packet_dispatched()
        if (ctx->payload_alloc)
            payload = (*ctx->payload_alloc)(cmd_pack->payload_len, ctx->user_data);
        else
            payload = malloc(cmd_pack->payload_len);
 
        if (!payload) {
            perror("malloc");
            exit(255);
        }

        packet += sizeof(cmd_packet_header_t);
        memcpy(payload, packet, cmd_pack->payload_len);
        packet += cmd_pack->payload_len;
        len -= sizeof(cmd_packet_header_t) + cmd_pack->payload_len;

        rmc_sub_packet_received(ctx, conn->connection_index,
                                cmd_pack->pid,
                                payload, cmd_pack->payload_len,
                                now, user_data_u32(conn->connection_index));

    }

    // Process received packages, moving consectutive ones
    // over to the ready queue.
    sub_process_received_packets(pub, &ctx->dispatch_ready);
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
        perror("rmc_proto::_process_multicast_read(): recvfrom()");
        return errno;
    }

    if (len < sizeof(multicast_header_t)) {
        fprintf(stderr, "Corrupt header. Needed [%lu] header bytes. Got [%lu]\n",
                sizeof(multicast_header_t), len);
        return EPROTO;
    }
                
    if (len < sizeof(multicast_header_t) + mcast_hdr->payload_len) {
        fprintf(stderr, "Corrupt packet. Needed [%lu + %d = %lu] header + payload bytes. Got %lu\n",
                sizeof(multicast_header_t),
                mcast_hdr->payload_len, 
                sizeof(multicast_header_t) + mcast_hdr->payload_len, len);
        return EPROTO;
    }
        
    strcpy(src_addr_str, inet_ntoa(src_addr.sin_addr));

    // If the publisher has a listen socket that is bound on all
    // interfaces (IF_ANY), we will see 0.0.0.0 as the
    // mcast_hdr->listen_ip. In these cases substitute this address
    // with the source address that the multicast packet came from.
    if (mcast_hdr->listen_ip == 0)
        mcast_hdr->listen_ip = ntohl(src_addr.sin_addr.s_addr);

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
                                         RMC_MULTICAST_INDEX,
                                         RMC_POLLREAD,
                                         RMC_POLLREAD);
        *read_res = RMC_READ_MULTICAST_LOOPBACK;
        return 0; // Loopback message
    }
    putchar('\n');


    // Find the socket we use to ack received packets back to the publisher.
    conn = rmc_conn_find_by_address(&ctx->conn_vec, mcast_hdr->listen_ip, mcast_hdr->listen_port);

    // If no socket is setup, initiate the connection to the publisher.
    // Drop the recived packet

    if (!conn || conn->mode == RMC_CONNECTION_MODE_CONNECTING) {
        res = _decode_unsubscribed_multicast(ctx,
                                             conn,
                                             data, mcast_hdr->payload_len,
                                             mcast_hdr->listen_ip, mcast_hdr->listen_port);

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

    res = _decode_subscribed_multicast(ctx, data, mcast_hdr->payload_len, conn);
        

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

static int _process_cmd_packet(rmc_connection_t* conn, user_data_t user_data)
{
    cmd_packet_header_t pack_hdr;
    uint8_t *payload = 0;
    char buf[RMC_MAX_PAYLOAD];
    rmc_sub_context_t* ctx = (rmc_sub_context_t*) user_data.ptr;
    
    circ_buf_read(&conn->read_buf, (uint8_t*) &pack_hdr, sizeof(pack_hdr), 0);
    circ_buf_free(&conn->read_buf, sizeof(pack_hdr), 0);


    circ_buf_read(&conn->read_buf, buf, pack_hdr.payload_len, 0);
    printf("_process_cmd_packet(): pid [%lu] payload[%s] len[%d]\n", pack_hdr.pid, buf,  pack_hdr.payload_len);
    
    if (sub_packet_is_duplicate(&ctx->publishers[conn->connection_index], pack_hdr.pid)) {
        circ_buf_free(&conn->read_buf, pack_hdr.payload_len, 0);
        printf("_process_cmd_packet(%lu): Duplicate\n",
               pack_hdr.pid);

        return 0; // Dups are ok.
    }

    if (ctx->payload_alloc)
        payload = (*ctx->payload_alloc)(pack_hdr.payload_len, ctx->user_data);
    else
        payload = malloc(pack_hdr.payload_len);

    if (!payload) {
        perror("_process_cmd_packet::memory alloc:");

        exit(255);
    }

    circ_buf_read(&conn->read_buf, payload, pack_hdr.payload_len, 0);
    circ_buf_free(&conn->read_buf, pack_hdr.payload_len, 0);


    rmc_sub_packet_received(ctx, conn->connection_index,
                            pack_hdr.pid,
                            payload,pack_hdr.payload_len,
                            rmc_usec_monotonic_timestamp(),
                            user_data_u32(conn->connection_index));

    return 0;
}



int rmc_sub_close_connection(rmc_sub_context_t* ctx, rmc_index_t s_ind)
{
    printf("rmc_sub_close_connection(): index[%d]\n", s_ind);


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
        { .command = RMC_CMD_PACKET, .dispatch = _process_cmd_packet },
        { .command = 0, .dispatch = 0 }
    };

    if (!ctx)
        return EINVAL;

    if (!op_res)
        op_res = &dummy_res;

    if (s_ind == RMC_MULTICAST_INDEX) 
        return _process_multicast_read(ctx, op_res);

    conn = rmc_conn_find_by_index(&ctx->conn_vec, s_ind);

    if (!conn || conn->mode != RMC_CONNECTION_MODE_CONNECTED) {
        *op_res = RMC_ERROR;

        return ENOTCONN;
    }

    res = rmc_conn_tcp_read(&ctx->conn_vec, s_ind, op_res,
                             dispatch_table, user_data_ptr(ctx));

    if (res == EPIPE) {
        *op_res = RMC_READ_DISCONNECT;
        rmc_sub_close_connection(ctx, s_ind);
        return 0; // This is not an error, just regular maintenance.
    }


    sub_process_received_packets(&ctx->publishers[s_ind], &ctx->dispatch_ready);

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

