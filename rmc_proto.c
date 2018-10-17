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
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <assert.h>

static int _get_free_slot(rmc_context_t* ctx)
{
    int i = 2; // First two slots are pre-allocated for multicast and listen
    
    while(i < RMC_MAX_SUBSCRIPTIONS) {
        if (ctx->sockets[i] == -1)
            return i;
        ++i;
    }
    return -1;
}


static int _process_multicast_write(rmc_context_t* ctx)
{
    pub_context_t* pctx = &ctx->pub_ctx;
    pub_packet_t* pack = pub_next_queued_packet(pctx);
    uint8_t packet[RMC_MAX_SUBSCRIPTIONS];
    uint8_t *packet_ptr = packet;
    payload_len_t *hdr_len = (payload_len_t*) packet_ptr;
    packet_id_t pid = 0;
    usec_timestamp_t ts = rmc_usec_monotonic_timestamp();
    ssize_t res = 0;
    
    // Initialize first two bytes (total multticast payload length) to 0.
    *hdr_len = 0;
    packet_ptr += sizeof(payload_len_t);

    while(pack &&
          *hdr_len <= RMC_MAX_SUBSCRIPTIONS) {

        *((packet_id_t*) packet_ptr) = pack->pid;
        packet_ptr += sizeof(packet_id_t);

        *((payload_len_t*) packet_ptr) = pack->payload_len;
        packet_ptr += sizeof(payload_len_t);
        
        memcpy(packet_ptr, pack->payload, pack->payload_len);
        packet_ptr += pack->payload_len;

        *hdr_len += sizeof(packet_id_t) + sizeof(payload_len_t) + pack->payload_len;
        pub_packet_sent(pctx, pack, ts);
        pack = pub_next_queued_packet(pctx);
    }

    res = sendto(ctx->sockets[RMC_MULTICAST_SOCKET_INDEX],
                 packet,
                 sizeof(payload_len_t) + *hdr_len,
                 0,                            
                 (struct sockaddr*) &ctx->mcast_dest_addr,
                 sizeof(ctx->mcast_dest_addr));

    if (res == -1)
        return errno;
    
    return 0;
    
}


static int _process_multicast_read(rmc_context_t* ctx)
{
    return 0;
}
    


    
static int _process_listen(rmc_context_t* ctx)
{
    return 0;
}


static int _process_subscription_read(rmc_context_t* ctx, int c_ind)
{
    return 0;
}


static int _process_subscription_write(rmc_context_t* ctx, int c_ind)
{
    return 0;
}


int rmc_init_context(rmc_context_t* ctx,
                     char* multicast_addr, 
                     int multicast_port,
                     char* listen_ip, // For subscription management
                     int listen_port, // For subscription management
                     void* (*payload_alloc)(payload_len_t),
                     void (*payload_free)(void*, payload_len_t),
                     void (*socket_added)(int, int), // Callback for each socket opened
                     void (*socket_deleted)(int, int))  // Callback for each socket closed.
{
    int i = sizeof(ctx->sockets) / sizeof(ctx->sockets[0]);

    assert(ctx);
    
    while(i--)
        ctx->sockets[i] = -1;

    strncpy(ctx->multicast_addr, multicast_addr, sizeof(ctx->multicast_addr));
    ctx->multicast_addr[sizeof(ctx->multicast_addr)-1] = 0;
    ctx->multicast_port = multicast_port;

    if (listen_ip) {
        strncpy(ctx->listen_ip, listen_ip, sizeof(ctx->listen_ip));
        ctx->listen_ip[sizeof(ctx->listen_ip)-1] = 0;
    } else
        ctx->listen_ip[0] = 0;

    ctx->listen_port = listen_port;
    ctx->socket_added = socket_added;
    ctx->socket_deleted = socket_deleted;
    ctx->payload_alloc = payload_alloc;
    ctx->payload_free = payload_free;

    pub_init_context(&ctx->pub_ctx, payload_free);
    sub_init_context(&ctx->sub_ctx, 0);

    return 0;
}


int rmc_listen(rmc_context_t* ctx)
{
    struct sockaddr_in sock_addr;
    struct ip_mreq mreq;
    int flag = 1;

    assert(ctx);


    ctx->sockets[RMC_MULTICAST_SOCKET_INDEX] = socket (AF_INET, SOCK_DGRAM, 0);
    if (ctx->sockets[RMC_MULTICAST_SOCKET_INDEX] == -1)
        return errno;

    if (setsockopt(ctx->sockets[RMC_MULTICAST_SOCKET_INDEX], SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
        perror("rmc_listen(): setsockopt(REUSEADDR)");
        return errno;
    }

    if (setsockopt(ctx->sockets[RMC_MULTICAST_SOCKET_INDEX], SOL_SOCKET, SO_REUSEPORT, &flag, sizeof(flag)) < 0) {
        perror("rmc_listen(): setsockopt(SO_REUSEPORT)");
        return errno;
    }

    // Join multicast group
    if (!inet_aton(ctx->multicast_addr, &mreq.imr_multiaddr))
        return EFAULT;

    mreq.imr_interface.s_addr = htonl(INADDR_ANY);         

    if (setsockopt(ctx->sockets[RMC_MULTICAST_SOCKET_INDEX], IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("rmc_listen(): setsockopt(IP_ADD_MEMBERSHIP)");
        return errno;
    }         

    // Bind to local endpoint.
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    sock_addr.sin_port = htons(ctx->multicast_port);

    if (bind(ctx->sockets[RMC_MULTICAST_SOCKET_INDEX], (struct sockaddr *) &sock_addr, sizeof(sock_addr)) < 0) {        
        perror("rmc_listen(): bind()");
        return errno;
    }    

    // setup remote endpoint
    memset((void*) &ctx->mcast_dest_addr, 0, sizeof(ctx->mcast_dest_addr));
    ctx->mcast_dest_addr.sin_family = AF_INET;
    ctx->mcast_dest_addr.sin_addr = mreq.imr_multiaddr;
    ctx->mcast_dest_addr.sin_port = htons(ctx->multicast_port);

    // Setup TCP listen
    // Did we specify a local interface address to bind to?
    ctx->sockets[RMC_LISTEN_SOCKET_INDEX] = socket (AF_INET, SOCK_STREAM, 0);
    if (ctx->sockets[RMC_LISTEN_SOCKET_INDEX] == -1)
        return errno;
    
    if (ctx->listen_ip[0]) {
        if (inet_aton(ctx->listen_ip, &sock_addr.sin_addr) != 1)
            return EFAULT;
    }
    else
        sock_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    sock_addr.sin_port = htons(ctx->listen_port);
    if (bind(ctx->sockets[RMC_LISTEN_SOCKET_INDEX], (struct sockaddr *) &sock_addr, sizeof(sock_addr)) < 0) {        
        perror("rmc_listen(): bind()");
        return errno;
    }    

    if (listen(ctx->sockets[RMC_LISTEN_SOCKET_INDEX], 5) != 0) {
        perror("rmc_listen(): listen()");
        return errno;
    }    
}



int rmc_connect_subscription(rmc_context_t* ctx,
                             char* server_addr,
                             int server_port,
                             int* result_socket,
                             int* result_connection_index)
{
    int c_ind = -1;
    struct hostent* host = 0;
    struct sockaddr_in sock_addr;

    assert(ctx);
    assert(server_addr);

    // Find a free slot.
    c_ind = _get_free_slot(ctx);
    if (c_ind == -1)
        return ENOMEM;

    ctx->sockets[c_ind] = socket (AF_INET, SOCK_STREAM, 0);
    if (ctx->sockets[c_ind] == -1)
        return errno;
    
    host = gethostbyname(server_addr);
    if (!host)
        return ENOENT;
            
    memcpy((void *) &sock_addr.sin_addr.s_addr, (void*) host->h_addr_list[0], host->h_length);
    sock_addr.sin_port = htons(server_port);
    sock_addr.sin_family = AF_INET;

    if (connect(ctx->sockets[c_ind], (struct sockaddr*) &sock_addr, sizeof(sock_addr))) {
        perror("rmc_connect():connect()");
        return errno;
    }       

    if (result_socket)
        *result_socket = ctx->sockets[c_ind];

    if (result_connection_index)
        *result_connection_index = c_ind;

    if (ctx->socket_added)
        (*ctx->socket_added)(ctx->sockets[c_ind], c_ind);

    
    return 0;
}



int rmc_read(rmc_context_t* ctx, int c_ind)
{

    assert(ctx);

    if (c_ind == RMC_MULTICAST_SOCKET_INDEX)
        return _process_multicast_read(ctx);

    if (c_ind == RMC_LISTEN_SOCKET_INDEX)
        return _process_listen(ctx);

    // Is c_ind within our socket vector?
    if (c_ind < 2 || c_ind >= RMC_MAX_SUBSCRIPTIONS)
        return EINVAL;

    if (ctx->sockets[c_ind] == -1)
        return ENOTCONN;

    // We have incoming data on a tcp subscription socket.
    return _process_subscription_read(ctx, c_ind);
}




int rmc_write(rmc_context_t* ctx, int c_ind)
{

    assert(ctx);

    if (c_ind == RMC_MULTICAST_SOCKET_INDEX)
        return _process_multicast_write(ctx);

    // Is c_ind within our socket vector?
    if (c_ind < 2 || c_ind >= RMC_MAX_SUBSCRIPTIONS)
        return EINVAL;

    if (ctx->sockets[c_ind] == -1)
        return ENOTCONN;

    // We have incoming data on a tcp subscription socket.
    return _process_subscription_write(ctx, c_ind);
}


int rmc_close_subscription(rmc_context_t* ctx, int c_ind)
{

    // Is c_ind within our socket vector?
    if (c_ind < 2 || c_ind >= RMC_MAX_SUBSCRIPTIONS)
        return EINVAL;

    if (ctx->sockets[c_ind] == -1)
        return ENOTCONN;

    if (shutdown(ctx->sockets[c_ind], SHUT_RDWR) != 0)
        return errno;

    if (close(ctx->sockets[c_ind]) != 0)
        return errno;

    ctx->sockets[c_ind] = 0;

}


int rmc_queue_packet(rmc_context_t* ctx, void* payload, payload_len_t payload_len)
{
    pub_queue_packet(&ctx->pub_ctx, payload, payload_len);
    return 0;
}
            


int rmc_get_socket_count(rmc_context_t* ctx, int *result)
{
    return 0;
}

int rmc_get_sockets(rmc_context_t* ctx, int* sockets, int* max_len)
{
    return 0;
}

int rmc_read_tcp(rmc_context_t* ctx)
{
    return 0;
}

static int decode_multicast(rmc_context_t* ctx,
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

        if (ctx->payload_alloc) 
            payload = (*ctx->payload_alloc)(payload_len);
        else
            payload = malloc(payload_len);
            
        if (!payload)
            return ENOMEM;

        memcpy(payload, packet, payload_len);
        packet += payload_len;

        if (!sub_packet_received(pub, pid, payload, payload_len)) {
            fprintf(stderr, "rmc_proto::decode_multicast(): Duplicate packet ID %lu. Ignored.\n", pid);
            if (ctx->payload_free) 
                (*ctx->payload_free)(payload, payload_len);
            else
                free(payload);
        }
        len -= (payload_len + sizeof(pid) + sizeof(payload_len));
    }

    // Process received packages, moving consectutive ones
    // over to the ready queue.
    sub_process_received_packets(pub);

    return 0;
}



int rmc_read_multicast(rmc_context_t* ctx)
{
    uint8_t buffer[RMC_MAX_PAYLOAD];
    payload_len_t payload_len;
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    ssize_t res;
    sub_publisher_t* pub = 0;
    if (!ctx)
        return EINVAL;

    if (ctx->sockets[RMC_MULTICAST_SOCKET_INDEX] == -1)
        return ENOTCONN;
    
    res = recvfrom(ctx->sockets[RMC_MULTICAST_SOCKET_INDEX],
                   buffer, sizeof(buffer),
                   MSG_DONTWAIT,
                   (struct sockaddr*) &src_addr, &addr_len);

    if (res == -1) {
        perror("rmc_proto::rmc_read_multicast(): recvfrom()");
        return errno;
    }
    
    pub = sub_find_publisher(&ctx->sub_ctx, &src_addr, addr_len);
    
    if (!pub) 
        pub = sub_add_publisher(&ctx->sub_ctx, &src_addr, addr_len);

    
    payload_len = *(payload_len_t*) buffer;
    return decode_multicast(ctx,
                            buffer + sizeof(payload_len_t),
                            payload_len,
                            pub);
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
    
