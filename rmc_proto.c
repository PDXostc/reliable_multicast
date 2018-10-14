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

#define RMC_MULTICAST_SOCKET 0
#define RMC_LISTEN_SOCKET 1


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



static int _process_multicast_read(rmc_context_t* ctx)
{
    return 0;
}
    

static int _process_multicast_write(rmc_context_t* ctx)
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


int rmc_init(rmc_context_t* ctx,
             char* multicast_addr, 
             int multicast_port,
             char* listen_ip, // For subscription management
             int listen_port, // For subscription management
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
        listen_ip[0] = 0;

    ctx->listen_port = listen_port;
    ctx->socket_added = socket_added;
    ctx->socket_deleted = socket_added;
    return 0;

}


int rmc_listen(rmc_context_t* ctx)
{
    struct sockaddr_in sock_addr;
    struct ip_mreq mreq;
    int flag = 1;

    assert(ctx);


    ctx->sockets[RMC_MULTICAST_SOCKET] = socket (AF_INET, SOCK_DGRAM, 0);
    if (ctx->sockets[RMC_MULTICAST_SOCKET] == -1)
        return errno;

    if (setsockopt(ctx->sockets[RMC_MULTICAST_SOCKET], SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
        perror("rmc_listen(): setsockopt(REUSEADDR)");
        return errno;
    }

    if (setsockopt(ctx->sockets[RMC_MULTICAST_SOCKET], SOL_SOCKET, SO_REUSEPORT, &flag, sizeof(flag)) < 0) {
        perror("rmc_listen(): setsockopt(SO_REUSEPORT)");
        return errno;
    }

    // Join multicast group
    if (!inet_aton(ctx->multicast_addr, &mreq.imr_multiaddr))
        return EFAULT;

    mreq.imr_interface.s_addr = htonl(INADDR_ANY);         

    if (setsockopt(ctx->sockets[RMC_MULTICAST_SOCKET], IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("rmc_listen(): setsockopt(IP_ADD_MEMBERSHIP)");
        return errno;
    }         

    // Bind to local endpoint.
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    sock_addr.sin_port = htons(ctx->multicast_port);

    if (bind(ctx->sockets[RMC_MULTICAST_SOCKET], (struct sockaddr *) &sock_addr, sizeof(sock_addr)) < 0) {        
        perror("rmc_listen(): bind()");
        return errno;
    }    


    // Setup TCP listen
    // Did we specify a local interface address to bind to?

    ctx->sockets[RMC_LISTEN_SOCKET] = socket (AF_INET, SOCK_STREAM, 0);
    if (ctx->sockets[RMC_LISTEN_SOCKET] == -1)
        return errno;
    
    if (ctx->listen_ip[0]) {
        if (inet_aton(ctx->listen_ip, &sock_addr.sin_addr) != 1)
            return EFAULT;
    }
    else
        sock_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    sock_addr.sin_port = htons(ctx->listen_port);
    if (bind(ctx->sockets[RMC_LISTEN_SOCKET], (struct sockaddr *) &sock_addr, sizeof(sock_addr)) < 0) {        
        perror("rmc_listen(): bind()");
        return errno;
    }    

    if (listen(ctx->sockets[RMC_LISTEN_SOCKET], 5) != 0) {
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

    if (c_ind == RMC_MULTICAST_SOCKET)
        return _process_multicast_read(ctx);

    if (c_ind == RMC_LISTEN_SOCKET)
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


    if (c_ind == RMC_MULTICAST_SOCKET)
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

int rmc_read_multicast(rmc_context_t* ctx)
{
    return 0;
}

int rmc_get_ready_packet_count(rmc_context_t* ctx)
{
    return 0;
}

int rmc_get_packet(rmc_context_t* ctx, void** packet, int* payload_len)
{
    return 0;
}

