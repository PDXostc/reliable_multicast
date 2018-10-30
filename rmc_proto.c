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

// =============
// SOCKET SLOT MANAGEMENT
// =============

static int _get_free_slot(rmc_context_t* ctx)
{
    int i = 2; // First two slots are pre-allocated for multicast and listen

    while(i < RMC_MAX_SOCKETS) {
        if (ctx->sockets[i].descriptor == -1) {
            if (ctx->max_socket_ind > i)
                ctx->max_socket_ind = i;

            return i;
        }            
        ++i;
    }
    return -1;
}

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


static void _reset_max_socket_ind(rmc_context_t* ctx)
{
    int ind = RMC_MAX_SOCKETS;

    while(ind) {
        if (ctx->sockets[ind].descriptor != -1) {
            ctx->max_socket_ind = ind;
            return;
        }
    }
    ctx->max_socket_ind = -1;
}


static void _reset_socket(rmc_socket_t* sock, int index)
{
    sock->poll_info.action = 0;
    sock->poll_info.rmc_index = index;
    sock->descriptor = -1;
    sock->mode = RMC_SOCKET_MODE_UNUSED;
    circ_buf_init(&sock->read_buf, sock->read_buf_data, sizeof(sock->read_buf_data));
    circ_buf_init(&sock->write_buf, sock->write_buf_data, sizeof(sock->write_buf_data));
    memset(&sock->remote_address, 0, sizeof(sock->remote_address));
}

// =============
// SOCKET CONNECT / ACCEPT / DISCONNECT
// =============

static int _connect_tcp_by_address(rmc_context_t* ctx,
                                   struct sockaddr_in* sock_addr,
                                   rmc_poll_index_t* result_index)
{
    rmc_poll_index_t c_ind = -1;

    assert(ctx);
    assert(sock_addr);

    // Find a free slot.
    c_ind = _get_free_slot(ctx);
    if (c_ind == -1)
        return ENOMEM;

    ctx->sockets[c_ind].descriptor = socket (AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

    if (ctx->sockets[c_ind].descriptor == -1)
        return errno;
 
    ctx->sockets[c_ind].poll_info.action = RMC_POLLREAD;

    if (connect(ctx->sockets[c_ind].descriptor,
                (struct sockaddr*) sock_addr,
                sizeof(*sock_addr))) {
        perror("rmc_connect():connect()");
        return errno;
    }

    // We are subscribing to data from the publisher, which
    // will resend failed multicast packets via tcp
    ctx->sockets[c_ind].mode = RMC_SOCKET_MODE_SUBSCRIBER;
    
    sub_init_publisher(&ctx->sockets[c_ind].pubsub.publisher,
                       &ctx->sub_ctx,
                       &ctx->sockets[c_ind]);

    memcpy(&ctx->sockets[c_ind].remote_address, sock_addr, sizeof(*sock_addr));

    if (ctx->poll_add)
        (*ctx->poll_add)(&ctx->sockets[c_ind].poll_info);

    if (result_index)
        *result_index = c_ind;

    return 0;
}


static int _connect_tcp_by_host(rmc_context_t* ctx,
                                char* server_addr,
                                rmc_poll_index_t* result_index)
{
    struct hostent* host = 0;
    struct sockaddr_in sock_addr;

    host = gethostbyname(server_addr);
    if (!host)
        return ENOENT;

    memcpy((void *) &sock_addr.sin_addr.s_addr,
           (void*) host->h_addr_list[0],
           host->h_length);

    sock_addr.sin_port = htons(ctx->port);
    sock_addr.sin_family = AF_INET;

    return _connect_tcp_by_address(ctx,
                                   &sock_addr,
                                   result_index);
}




static int _process_accept(rmc_context_t* ctx,
                           rmc_poll_index_t* result_index)
{
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    rmc_poll_index_t c_ind = -1;

    // Find a free slot.
    c_ind = _get_free_slot(ctx);
    if (c_ind == -1)
        return ENOMEM;

    ctx->sockets[c_ind].descriptor = accept4(ctx->sockets[RMC_LISTEN_SOCKET_INDEX].descriptor,
                                             (struct sockaddr*) &src_addr,
                                             &addr_len, SOCK_NONBLOCK);

    if (ctx->sockets[c_ind].descriptor == -1)
        return errno;


    // The remote end is the subscriber of packets that we pulish
    pub_init_subscriber(&ctx->sockets[c_ind].pubsub.subscriber, &ctx->pub_ctx, &ctx->sockets[c_ind]);
    ctx->sockets[c_ind].mode = RMC_SOCKET_MODE_PUBLISHER;
    memcpy(&ctx->sockets[c_ind].remote_address, &src_addr, sizeof(src_addr));

    if (ctx->poll_add)
        (*ctx->poll_add)(&ctx->sockets[c_ind].poll_info);

    if (result_index)
        *result_index = c_ind;

    return 0;
}

static int _process_cmd_init(rmc_context_t* ctx, rmc_socket_t* sock, payload_len_t len)
{
    return 0;
}

static int _process_cmd_init_reply(rmc_context_t* ctx, rmc_socket_t* sock, payload_len_t len)
{
    return 0;
}

static int _process_cmd_packet(rmc_context_t* ctx, rmc_socket_t* sock, payload_len_t len)
{
    return 0;
}

static int _process_cmd_ack(rmc_context_t* ctx, rmc_socket_t* sock, payload_len_t len)
{
    return 0;
}

static int _process_tcp_command(rmc_context_t* ctx, rmc_socket_t* sock,
                         uint8_t cmd, payload_len_t len)
{
    switch(cmd) {
    case RMC_CMD_INIT:
        return _process_cmd_init(ctx, sock, len);

    case RMC_CMD_INIT_REPLY:
        return _process_cmd_init_reply(ctx, sock, len);

    case RMC_CMD_PACKET:
        return _process_cmd_packet(ctx, sock, len);

    case RMC_CMD_ACK:
        return _process_cmd_ack(ctx, sock, len);

    }
    return ENOENT; // Command not found.
}



int rmc_close_tcp(rmc_context_t* ctx, rmc_poll_index_t p_ind)
{

    // Is p_ind within our socket vector?
    if (p_ind < 2 || p_ind >= RMC_MAX_SOCKETS)
        return EINVAL;

    if (ctx->sockets[p_ind].descriptor == -1)
        return ENOTCONN;

    if (shutdown(ctx->sockets[p_ind].descriptor, SHUT_RDWR) != 0)
        return errno;

    if (close(ctx->sockets[p_ind].descriptor) != 0)
        return errno;

    _reset_socket(&ctx->sockets[p_ind], p_ind);

    if (ctx->poll_remove)
        (*ctx->poll_remove)(&ctx->sockets[p_ind].poll_info);

    if (p_ind == ctx->max_socket_ind)
        _reset_max_socket_ind(ctx);
    
}




// =============
// CONTEXT MANAGEMENT
// =============
int rmc_init_context(rmc_context_t* ctx,
                     char* multicast_addr,
                     char* listen_ip,
                     int port,
                     void* (*payload_alloc)(payload_len_t),
                     void (*payload_free)(void*, payload_len_t),
                     void (*poll_add)(rmc_poll_t* poll),
                     void (*poll_remove)(rmc_poll_t* poll)) {

    int i = sizeof(ctx->sockets) / sizeof(ctx->sockets[0]);

    assert(ctx);

    while(i--) 
        _reset_socket(&ctx->sockets[i], i);
    

    strncpy(ctx->multicast_addr, multicast_addr, sizeof(ctx->multicast_addr));
    ctx->multicast_addr[sizeof(ctx->multicast_addr)-1] = 0;

    if (listen_ip) {
        strncpy(ctx->listen_ip, listen_ip, sizeof(ctx->listen_ip));
        ctx->listen_ip[sizeof(ctx->listen_ip)-1] = 0;
    } else
        ctx->listen_ip[0] = 0;

    ctx->port = port;
    ctx->poll_add = poll_add;
    ctx->poll_remove = poll_remove;
    ctx->payload_alloc = payload_alloc;
    ctx->payload_free = payload_free;
    ctx->socket_count = 0;
    ctx->max_socket_ind = -1;
    ctx->resend_timeout = RMC_RESEND_TIMEOUT_DEFAULT;

    // outgoing_payload_free() will be called when
    // pub_acket_ack() is called, which happens when a
    // subscriber sends an ack back for the given pid.
    // When all subscribers have acknowledged,
    // outgoing_payload_free() is called to free the payload.
    pub_init_context(&ctx->pub_ctx, payload_free);
    sub_init_context(&ctx->sub_ctx, 0);

    return 0;
}


int rmc_activate_context(rmc_context_t* ctx)
{
    struct sockaddr_in sock_addr;
    struct ip_mreq mreq;
    int flag = 1;

    if (!ctx)
        return EINVAL;


    if (ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].descriptor != -1)
        return EEXIST;

    ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].descriptor = socket (AF_INET, SOCK_DGRAM, 0);

    if (ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].descriptor == -1) {
        perror("rmc_listen(): socket(multicast)");
        goto error;
    }

    if (setsockopt(ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].descriptor, SOL_SOCKET,
                   SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
        perror("rmc_listen(): setsockopt(REUSEADDR)");
        goto error;
    }

    if (setsockopt(ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].descriptor, SOL_SOCKET,
                   SO_REUSEPORT, &flag, sizeof(flag)) < 0) {
        perror("rmc_listen(): setsockopt(SO_REUSEPORT)");
        goto error;
    }

    // Join multicast group
    if (!inet_aton(ctx->multicast_addr, &mreq.imr_multiaddr))
        goto error;


    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    if (setsockopt(ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].descriptor,
                   IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("rmc_listen(): setsockopt(IP_ADD_MEMBERSHIP)");
        goto error;
    }

    // Bind to local endpoint.
//    sock_addr.sin_family = AF_INET;
//    sock_addr.sin_addr.s_addr = htonl(INADDR_ANY);
//    sock_addr.sin_port = htons(INPORT_ANY);

//    if (bind(ctx->sockets[RMC_MULTICAST_SOCKET_INDEX],
//             (struct sockaddr *) &sock_addr, sizeof(sock_addr)) < 0) {
//        perror("rmc_listen(): bind()");
//        return errno;
//    }

    // setup remote endpoint
    memset((void*) &ctx->mcast_dest_addr, 0, sizeof(ctx->mcast_dest_addr));
    ctx->mcast_dest_addr.sin_family = AF_INET;
    ctx->mcast_dest_addr.sin_addr = mreq.imr_multiaddr;
    ctx->mcast_dest_addr.sin_port = htons(ctx->port);

    // Setup TCP listen
    // Did we specify a local interface address to bind to?
    ctx->sockets[RMC_LISTEN_SOCKET_INDEX].descriptor = socket (AF_INET, SOCK_STREAM, 0);
    if (ctx->sockets[RMC_LISTEN_SOCKET_INDEX].descriptor == -1) {
        perror("rmc_listen(): socket(listen)");
        goto error;
    }

    if (ctx->listen_ip[0] &&
        inet_aton(ctx->listen_ip, &sock_addr.sin_addr) != 1) {
        errno = EFAULT;
        goto error;
    }
    else
        sock_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    sock_addr.sin_port = htons(ctx->port);
    if (bind(ctx->sockets[RMC_LISTEN_SOCKET_INDEX].descriptor,
             (struct sockaddr *) &sock_addr, sizeof(sock_addr)) < 0) {
        perror("rmc_listen(): bind()");
        goto error;
    }

    if (listen(ctx->sockets[RMC_LISTEN_SOCKET_INDEX].descriptor, RMC_LISTEN_SOCKET_BACKLOG) != 0) {
        perror("rmc_listen(): listen()");
        goto error;
    }

    ctx->socket_count += 2;

    if (ctx->max_socket_ind < RMC_LISTEN_SOCKET_INDEX)
        ctx->max_socket_ind = RMC_LISTEN_SOCKET_INDEX;

    if (ctx->max_socket_ind < RMC_MULTICAST_SOCKET_INDEX)
        ctx->max_socket_ind = RMC_MULTICAST_SOCKET_INDEX;

    ctx->sockets[RMC_LISTEN_SOCKET_INDEX].poll_info.action = RMC_POLLREAD;
    ctx->sockets[RMC_LISTEN_SOCKET_INDEX].mode = RMC_SOCKET_MODE_OTHER;

    ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].poll_info.action = RMC_POLLREAD;
    ctx->sockets[RMC_LISTEN_SOCKET_INDEX].mode = RMC_SOCKET_MODE_OTHER;
    

    if (ctx->poll_add) {
        (*ctx->poll_add)(&ctx->sockets[RMC_LISTEN_SOCKET_INDEX].poll_info);
        (*ctx->poll_add)(&ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].poll_info);
    }

    return 0;

error:
    if (ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].descriptor != -1) {
        close(ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].descriptor);
        _reset_socket(&ctx->sockets[RMC_MULTICAST_SOCKET_INDEX], RMC_MULTICAST_SOCKET_INDEX);
    }

    if (ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].descriptor != -1) {
        close(ctx->sockets[RMC_LISTEN_SOCKET_INDEX].descriptor);
        _reset_socket(&ctx->sockets[RMC_LISTEN_SOCKET_INDEX], RMC_MULTICAST_SOCKET_INDEX);
    }

    return errno;
}

int rmc_deactivate_context(rmc_context_t* ctx)
{
    return 0;
}


// =============
// TIMEOUT MANAGEMENT
// =============
static void _process_packet_timeout(rmc_context_t* ctx, pub_subscriber_t* sub, pub_packet_t* pack, usec_timestamp_t timeout_ts)
{
    // Send the packet via TCP.
    rmc_socket_t* sock = (rmc_socket_t*) pub_subscriber_user_data(sub);

}


static void _process_subscriber_timeout(rmc_context_t* ctx, pub_subscriber_t* sub, usec_timestamp_t timeout_ts)
{
    pub_packet_list_t packets;

    pub_packet_list_init(&packets, 0, 0, 0);

    pub_get_timed_out_packets(sub, timeout_ts, &packets);

    pub_packet_list_for_each_rev(&packets,
                                 lambda(uint8_t, (pub_packet_node_t* pnode, void* udata) {
                                         _process_packet_timeout(ctx, sub, pnode->data, timeout_ts);
                                  return 1;
                              }), 0);

                              
}


int rmc_get_next_timeout(rmc_context_t* ctx, usec_timestamp_t* result)
{
    usec_timestamp_t ts = rmc_usec_monotonic_timestamp();
    pub_subscriber_t* sub = 0;
    pub_packet_t* pack = 0;

    if (!ctx || !result)
        return EINVAL;
    
    // Query the publisher for all 
    pub_get_oldest_subscriber(&ctx->pub_ctx, &sub, &pack);

    // If no subscriber has inflight packets, then set result to 0.
    if (!sub) {
        *result = 0;
        return ENODATA;
    }

    // Has our oldest packet already expired?
    if (pack->send_ts <= ts - ctx->resend_timeout) {
        *result = 0;
        return 0;
    }

    *result =  (ts - ctx->resend_timeout) - (ts - pack->send_ts);
    return 0;
}

int rmc_process_timeout(rmc_context_t* ctx)
{
    usec_timestamp_t ts = rmc_usec_monotonic_timestamp();
    pub_sub_list_t subs;

    if (!ctx)
        return EINVAL;
    
    pub_sub_list_init(&subs, 0, 0, 0);
    pub_get_timed_out_subscribers(&ctx->pub_ctx, ts - ctx->resend_timeout, &subs);
    pub_sub_list_for_each(&subs,
                          // For each subscriber, check if their oldest inflight packet has a sent_ts
                          // timestamp older than max_age. If so, add it to result.
                          lambda(uint8_t, (pub_sub_node_t* sub_node, void* udata) {
                                  _process_subscriber_timeout(ctx, sub_node->data, ts - ctx->resend_timeout);
                                  return 1;
                              }), 0);
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
        int res = _connect_tcp_by_address(ctx, &src_addr, &sock_ind);
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


// Return EAGAIN if we have a partial command that needs to more data
// to be processed.
// EAGAIN can be returned if one or more commands have been executed
// and it is the last command that is partial.
///
static int _process_tcp_read(rmc_context_t* ctx, rmc_poll_index_t p_ind)
{
    rmc_socket_t* sock = &ctx->sockets[p_ind];
    uint32_t in_use = circ_buf_available(&sock->read_buf);;
    cmd_t cmd;


    // Loop through all commands.
    while(in_use >= sizeof(cmd_t)) {
        uint32_t len = 0;
        int res = 0;

        res = circ_buf_read(&sock->read_buf, (uint8_t*) &cmd, sizeof(cmd), &len);

        if (res)
            return res;

        // Do we need more data for the command header?
        //
        if (len - sizeof(cmd_t) < cmd.length)
            return 0;


        // Process the TCP command.
        // If the return value is EAGAIN, then we don't have enough
        // data in sock->read_buf to process the entire command.
        // Return and try again later when we have more data.
        res = _process_tcp_command(ctx, sock, cmd.command, cmd.length);

        if (res)
            return res;

        // Free the number of the bytes that cmd occupies.
        // _process_tcp_command() will have freed the number of bytes
        // taken up by whatever the command payload itself takes up,
        // leaving the first byte of the remaining data in use to be
        // the start of the next command.
        circ_buf_free(&sock->read_buf, sizeof(cmd), &in_use);
    }
    return 0;
}


int rmc_read(rmc_context_t* ctx, rmc_poll_index_t p_ind, uint16_t* new_poll_action)
{
    int res = 0;
    if (!ctx)
        return EINVAL;

    if (p_ind == RMC_MULTICAST_SOCKET_INDEX) {
        res = _process_multicast_read(ctx);
        *new_poll_action = ctx->sockets[p_ind].poll_info.action;
    }

    if (p_ind == RMC_LISTEN_SOCKET_INDEX) {
        res = _process_accept(ctx, &p_ind);
        *new_poll_action = ctx->sockets[p_ind].poll_info.action;
        return res;
    }

    // Is c_ind within our socket vector?
    if (p_ind < 2 || p_ind >= RMC_MAX_SOCKETS)
        return EINVAL;

    if (ctx->sockets[p_ind].descriptor == -1)
        return ENOTCONN;

    // We have incoming data on a  tcp socket.
    *new_poll_action = ctx->sockets[p_ind].poll_info.action;
    return _process_tcp_read(ctx, p_ind);
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

int rmc_write(rmc_context_t* ctx, rmc_poll_index_t p_ind, uint16_t* new_poll_action)
{
    int res = 0;
    int rearm_write = 0;
    uint32_t bytes_left_before = 0;
    uint32_t bytes_left_after = 0;

    assert(ctx);

    if (p_ind == RMC_MULTICAST_SOCKET_INDEX) {
        res = _process_multicast_write(ctx);
        *new_poll_action = ctx->sockets[p_ind].poll_info.action;
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
    
    if (bytes_left_after == 0) 
        *new_poll_action = ctx->sockets[p_ind].poll_info.action &= ~RMC_POLLWRITE;
    else
        *new_poll_action = ctx->sockets[p_ind].poll_info.action |= RMC_POLLWRITE;

    if (ctx->poll_modify)
        (*ctx->poll_modify)(&ctx->sockets[p_ind].poll_info);

    return res;
}




 
int rmc_queue_packet(rmc_context_t* ctx,
                     void* payload,
                     payload_len_t payload_len)
{
    pub_queue_packet(&ctx->pub_ctx, payload, payload_len);

    return 0;
}


int rmc_get_poll_size(rmc_context_t* ctx, int *result)
{
    if (!ctx || !result)
        return EINVAL;

    *result = ctx->socket_count;

    return 0;
}


int rmc_get_poll_vector(rmc_context_t* ctx, rmc_poll_t* result, int* len)
{
    int ind = 0;
    int res_ind;
    int max_len = 0;

    if (!ctx || !result || !len)
        return EINVAL;

    max_len = *len;

    while(ind < ctx->max_socket_ind && res_ind < max_len) {
        if (ctx->sockets[ind].descriptor != -1)
            result[res_ind++] = ctx->sockets[ind].poll_info;

        ind++;
    }

    *len = res_ind;
}

int rmc_get_ready_packet_count(rmc_context_t* ctx)
{
    return sub_get_ready_packet_count(&ctx->sub_ctx);
}

sub_packet_t* rmc_get_next_ready_packet(rmc_context_t* ctx)
{
    return sub_get_next_ready_packet(&ctx->sub_ctx);
}

void rmc_free_packet(sub_packet_t* packet)
{
    sub_packet_dispatched(packet);
}
