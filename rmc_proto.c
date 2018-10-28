// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)



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

static int _get_free_slot(rmc_context_t* ctx)
{
    int i = 2; // First two slots are pre-allocated for multicast and listen

    while(i < RMC_MAX_SOCKETS) {
        if (ctx->sockets[i].descriptor == -1)
            return i;
        ++i;
    }

    return -1;
}


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



static int _rmc_connect_tcp_by_address(rmc_context_t* ctx,
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

    ctx->sockets[c_ind].descriptor = socket (AF_INET, SOCK_STREAM, 0);
    if (ctx->sockets[c_ind].descriptor == -1)
        return errno;

    ctx->sockets[c_ind].poll_info.action = RMC_POLLREAD;

    if (connect(ctx->sockets[c_ind].descriptor,
                (struct sockaddr*) sock_addr, sizeof(*sock_addr))) {
        perror("rmc_connect():connect()");
        return errno;
    }


    if (ctx->poll_add)
        (*ctx->poll_add)(&ctx->sockets[c_ind].poll_info);

    if (result_index)
        *result_index = c_ind;

    return 0;
}

static int _rmc_connect_tcp_by_host(rmc_context_t* ctx,
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

    return _rmc_connect_tcp_by_address(ctx,
                                       &sock_addr,
                                       result_index);
}


static int _process_multicast_read(rmc_context_t* ctx)
{
    uint8_t buffer[RMC_MAX_PAYLOAD];
    payload_len_t payload_len;
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    ssize_t res;
    sub_publisher_t* pub = 0;

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

    pub = sub_find_publisher(&ctx->sub_ctx, &src_addr, addr_len);

    // No publisher found?
    if (!pub) {
        // Add an outbound tcp connection to the publisher.
        int res = _rmc_connect_tcp_by_address(ctx, &src_addr, 0);
        if (res)
            return res;

        pub = sub_add_publisher(&ctx->sub_ctx, &src_addr, addr_len);
    }

    payload_len = *(payload_len_t*) buffer;

    return _decode_multicast(ctx,
                             buffer + sizeof(payload_len_t),
                             payload_len,
                             pub);
}


static int _process_listen(rmc_context_t* ctx)
{

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


// Return EAGAIN if we have a partial command that needs to more data
// to be processed.
// EAGAIN can be returned if one or more commands have been executed
// and it is the last command that is partial.
///
static int _process_tcp_read(rmc_context_t* ctx, rmc_poll_index_t p_ind)
{
    rmc_socket_t* sock = &ctx->sockets[p_ind];
    uint32_t in_use = circ_buf_available(&sock->circ_buf);;
    cmd_t cmd;


    // Loop through all commands.
    while(in_use >= sizeof(cmd_t)) {
        uint32_t len = 0;
        int res = 0;

        res = circ_buf_read(&sock->circ_buf, (uint8_t*) &cmd, sizeof(cmd), &len);

        if (res)
            return res;

        // Do we need more data for the command header?
        //
        if (len - sizeof(cmd_t) < cmd.length)
            return 0;


        // Process the TCP command.
        // If the return value is EAGAIN, then we don't have enough
        // data in sock->circ_buf to process the entire command.
        // Return and try again later when we have more data.
        res = _process_tcp_command(ctx, sock, cmd.command, cmd.length);

        if (res)
            return res;

        // Free the number of the bytes that cmd occupies.
        // _process_tcp_command() will have freed the number of bytes
        // taken up by whatever the command payload itself takes up,
        // Leaving the first byte of the remaining data in use to be
        // the start of the next command.
        circ_buf_free(&sock->circ_buf, sizeof(cmd), &in_use);
    }
    return 0;
}

static int _process_tcp_write(rmc_context_t* ctx, rmc_poll_index_t p_ind)
{
    return 0;
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
    circ_buf_init(&sock->circ_buf, sock->circ_buf_data, sizeof(sock->circ_buf_data));
}

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
    ctx->resend_retries = RMC_RESEND_RETRIES;

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
    ctx->sockets[RMC_MULTICAST_SOCKET_INDEX].poll_info.action = RMC_POLLREAD;

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

int rmc_get_next_timeout(rmc_context_t* ctx, usec_timestamp_t* result)
{
    usec_timestamp_t ts = 0;

    if (!ctx || !result)
        return EINVAL;

    // Iterate over all publishers and take the first (oldest) elemen and check its timestamp
}

int rmc_process_timeout(rmc_context_t* context);

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
        res = _process_listen(ctx);
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


int rmc_write(rmc_context_t* ctx, rmc_poll_index_t p_ind, uint16_t* new_poll_action)
{
    int res = 0;
    int rearm_write = 0;
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

    // We have incoming data on a tcp tcp socket.
    res = _process_tcp_write(ctx, p_ind);

    // Return whatever action is set after _process_tcp_write returns.
    *new_poll_action = ctx->sockets[p_ind].poll_info.action;

    return res;
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

    if (ctx->sockets[p_ind].descriptor == ctx->max_socket_ind)
        _reset_max_socket_ind(ctx);

    _reset_socket(&ctx->sockets[p_ind], p_ind);

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
