// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)


#define _GNU_SOURCE
#include "reliable_multicast.h"
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
static int _process_multicast_write(rmc_pub_context_t* ctx)
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
    mcast_hdr->listen_ip = ctx->control_listen_if_addr; 
    mcast_hdr->listen_port = ctx->control_listen_port; 

    packet_ptr += sizeof(multicast_header_t);

    pub_packet_list_init(&snd_list, 0, 0, 0);

    listen_addr = inet_ntoa( (struct in_addr) { .s_addr = htonl(ctx->control_listen_if_addr) });
    mcast_addr = inet_ntoa( (struct in_addr) { .s_addr = htonl(ctx->mcast_group_addr) });

    printf("mcast_tx(): mcast[%s:%d] listen[%s:%d]",
           mcast_addr, ntohs(sock_addr.sin_port),
           listen_addr, mcast_hdr->listen_port);

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

        printf(" pid[%lu]", pack->pid);
        // FIXME: Maybe add a specific API call to traverse queued packages?
        pnode = pub_packet_list_prev(pack->parent_node);
        pack = pnode?pnode->data:0;
    }

    printf(" - len[%.5d]\n", mcast_hdr->payload_len);

    res = sendto(ctx->mcast_send_descriptor,
                 packet,
                 sizeof(multicast_header_t) + mcast_hdr->payload_len,
                 MSG_DONTWAIT,
                 (struct sockaddr*) &sock_addr,
                 sizeof(sock_addr));

    if (res == -1) {
        if ( errno != EAGAIN && errno != EWOULDBLOCK)
            return errno;

        if (ctx->conn_vec.poll_modify) {
            (*ctx->conn_vec.poll_modify)(ctx->user_data,
                                         ctx->mcast_send_descriptor,
                                         RMC_MULTICAST_INDEX,
                                         RMC_POLLWRITE,
                                         RMC_POLLWRITE);
        }
        return 0;
    }

    ts = rmc_usec_monotonic_timestamp();

    // Mark all packages in the multicast packet we just
    // sent in the multicast message as sent.
    // pub_packet_sent will call free_o
    while(pub_packet_list_pop_head(&snd_list, &pack)) 
        pub_packet_sent(pctx, pack, ts);


//    extern void test_print_pub_context(pub_context_t* ctx);
//    test_print_pub_context(&ctx->pub_ctx);

    if (ctx->conn_vec.poll_modify) {
        // Do we have more packets to send?
        (*ctx->conn_vec.poll_modify)(ctx->user_data,
                            ctx->mcast_send_descriptor,
                            RMC_MULTICAST_INDEX,
                            RMC_POLLWRITE,
                            pub_next_queued_packet(pctx)?RMC_POLLWRITE:0);
    }
    return 0;
}



int rmc_pub_write(rmc_pub_context_t* ctx, rmc_connection_index_t s_ind, uint8_t* op_res)
{
    int res = 0;
    int rearm_write = 0;
    uint32_t bytes_left_before = 0;
    uint32_t bytes_left_after = 0;
    rmc_poll_action_t old_action;
    rmc_connection_t* conn = 0;
    assert(ctx);

    if (s_ind == RMC_MULTICAST_INDEX) {
        if (op_res)
            *op_res = RMC_WRITE_MULTICAST;
        return _process_multicast_write(ctx);
    }

    // Is s_ind within our connection vector?
    if (s_ind >= RMC_MAX_CONNECTIONS) {
        if (op_res)
            *op_res = RMC_ERROR;

        return EINVAL;
    }

    conn = _rmc_conn_find_by_index(&ctx->conn_vec, s_ind);

    if (conn->descriptor == -1) {
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
    
    res = _rmc_conn_process_tcp_write(conn, &bytes_left_after);
    
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