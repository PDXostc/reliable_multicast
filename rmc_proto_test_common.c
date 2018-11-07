// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "rmc_proto_test_common.h"


// We need user data that points out both
// the pollset file descriptor and the context associated.

char* _index(rmc_connection_index_t index, char* res)
{
    switch(index) {
    case RMC_MULTICAST_SEND_INDEX:
        return strcpy(res, "mcast_send");

    case RMC_MULTICAST_RECV_INDEX:
        return strcpy(res, "mcast_recv");


    case RMC_LISTEN_INDEX:
        return strcpy(res, "listen");

    default:
        sprintf(res, "%.3d", index);
        return res;
    }
    return 0;
}

int _descriptor(rmc_context_t* ctx,
                       rmc_connection_index_t index)
{
    switch(index) {
    case RMC_MULTICAST_RECV_INDEX:
        return ctx->mcast_recv_descriptor;

    case RMC_MULTICAST_SEND_INDEX:
        return ctx->mcast_send_descriptor;

    case RMC_LISTEN_INDEX:
        return ctx->listen_descriptor;

    default:
        return ctx->connections[index].descriptor;

    }
}


void* _test_proto_alloc(payload_len_t plen)
{
    void* res = malloc(plen);

    assert(res);
    return res;
}

void test_proto_free(void* payload, payload_len_t plen)
{
    free(payload);
    return;
}


void _test(char* fmt_string, int major, int minor, int error)
{
    if (!error)
        return;

    printf(fmt_string, major, minor, strerror(error));
    exit(255);
}


void poll_add(rmc_context_t* ctx,
              int descriptor,
              rmc_connection_index_t index,
              rmc_poll_action_t action)
{
    char buf[16];
    int epollfd = rmc_user_data(ctx).i32;
    struct epoll_event ev = {
        .data.u32 = index,
        .events = EPOLLONESHOT
    };

    if (action & RMC_POLLREAD)
        ev.events |= EPOLLIN;

    if (action & RMC_POLLWRITE)
        ev.events |= EPOLLOUT;

    printf("poll_add(%s:%d)%s%s%s\n",
           _index(index, buf),
           descriptor,
           ((action & RMC_POLLREAD)?" read":""),
           ((action & RMC_POLLWRITE)?" write":""),
           (!(action & (RMC_POLLREAD | RMC_POLLWRITE)))?" [none]":"");

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, descriptor, &ev) == -1) {
        perror("epoll_ctl(add)");
        exit(255);
    }
}



void poll_modify(rmc_context_t* ctx,
                 int descriptor,
                 rmc_connection_index_t index,
                 rmc_poll_action_t old_action,
                 rmc_poll_action_t new_action)
{
    char buf[16];
    int epollfd = rmc_user_data(ctx).i32;
    struct epoll_event ev = {
        .data.u32 = index,
        .events = EPOLLONESHOT
    };

    if (new_action & RMC_POLLREAD)
        ev.events |= EPOLLIN;

    if (new_action & RMC_POLLWRITE)
        ev.events |= EPOLLOUT;

    printf("poll_modify(%s:%d)%s%s%s\n",
           _index(index, buf),
           descriptor,
           ((new_action & RMC_POLLREAD)?" read":""),
           ((new_action & RMC_POLLWRITE)?" write":""),
           (!(new_action & (RMC_POLLREAD | RMC_POLLWRITE)))?" [none]":"");

    if (epoll_ctl(epollfd, EPOLL_CTL_MOD, descriptor, &ev) == -1) {
        perror("epoll_ctl(modify)");
        exit(255);
    }
}


void poll_remove(rmc_context_t* ctx,
                 int descriptor,
                 rmc_connection_index_t index)
{
    char buf[16];
    int epollfd = rmc_user_data(ctx).i32;

    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, descriptor, 0) == -1) {
        perror("epoll_ctl(delete)");
        exit(255);
    }
    printf("poll_remove(%s)\n", _index(index, buf));
}


int process_packet(rmc_context_t* ctx, int major, int minor)
{
    sub_packet_t* pack = 0;

    pack = rmc_get_next_ready_packet(ctx);
    _test("rmc_proto_test[%d.%d] process_packet():rmc_get_next_ready_packet(): %s\n", major, minor, pack?0:ENODATA);

    return minor + 1;
}


int process_events(rmc_context_t* ctx, int epollfd, int major)
{
    struct epoll_event events[RMC_MAX_CONNECTIONS];
    char buf[16];
    usec_timestamp_t tout = 0;
    int nfds = 0;
        
    // Get the next timeout 
    // If we get ENODATA back, it means that we have no timeouts queued.
    if (rmc_get_next_timeout(ctx, &tout) == ENODATA)
        tout = 100000; // 100 msec.


    nfds = epoll_wait(epollfd, events, RMC_MAX_CONNECTIONS, tout / 1000);
    if (nfds == -1) {
        perror("epoll_wait");
        exit(255);
    }

    // Timeout
    if (nfds == 0) {
        rmc_process_timeout(ctx);
        return ETIME;
    }

    printf("poll_wait(): %d results\n", nfds);

    while(nfds--) {
        int res = 0;
        rmc_connection_index_t c_ind = events[nfds].data.u64 & 0xFFFFFFFF;

        // Figure out which context that triggered the event.

        printf("poll_wait(%s:%d)%s%s%s\n",
               _index(c_ind, buf), _descriptor(ctx, c_ind),
               ((events[nfds].events & EPOLLIN)?" read":""),

               ((events[nfds].events & EPOLLOUT)?" write":""),
               ((events[nfds].events & EPOLLHUP)?" disconnect":""));

        if (events[nfds].events & EPOLLIN) {
            res = rmc_read(ctx, events[nfds].data.u32);

            // Did we read a loopback message we sent ourselves?
            if (res == ELOOP)
                continue;

            _test("rmc_proto_test[%d.%d] process_events():rmc_read(): %s\n", major, 1, res);
                
            // If this was a connection call processed, we can continue.
            if (events[nfds].data.u32 == RMC_LISTEN_INDEX)
                continue;
                    
            process_packet(ctx, 3, 2);
        }

        if (events[nfds].events & EPOLLOUT) 
            _test("rmc_proto_test[%d.%d] process_events():rmc_write(): %s\n",
                  major, 10,
                  rmc_write(ctx, c_ind));

        if (events[nfds].events & EPOLLHUP) 
            _test("rmc_proto_test[%d.%d] process_events():rmc_close_tcp(): %s\n",
                  major, 11, rmc_close_tcp(ctx, c_ind));
    }
    return 0;
}


