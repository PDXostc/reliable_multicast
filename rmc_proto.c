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
