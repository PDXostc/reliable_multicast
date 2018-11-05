// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "rmc_proto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>


// We need user data that points out both
// the pollset file descriptor and the context associated.

static char* _index(rmc_connection_index_t index, char* res)
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

static void* _test_proto_alloc(payload_len_t plen)
{
    void* res = malloc(plen);

    assert(res);
    return res;
}

static void test_proto_free(void* payload, payload_len_t plen)
{
    free(payload);
    return;
}


static void _test(char* tst, int error)
{
    if (!error)
        return;

    printf("RMC protocol test %s: %s\n", tst, strerror(error));
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
        // Store both rmc context id and connection index, allowing us to
        // determine which context got triggered.
        .data.u64 = ((uint64_t) rmc_context_id(ctx)) << 32 | index,
        .events = EPOLLONESHOT
    };

    if (action & RMC_POLLREAD)
        ev.events |= EPOLLIN;

    if (action & RMC_POLLWRITE)
        ev.events |= EPOLLOUT;

    printf("poll_add(%s)%s%s%s\n",
           _index(index, buf),
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
        .data.u64 = ((uint64_t) rmc_context_id(ctx)) << 32 | index,
        .events = EPOLLONESHOT
    };

    if (new_action & RMC_POLLREAD)
        ev.events |= EPOLLIN;

    if (new_action & RMC_POLLWRITE)
        ev.events |= EPOLLOUT;

    printf("poll_modify(%s)%s%s%s\n",
           _index(index, buf),
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



#define PUBLISH 1
#define SUBSCRIBE 2
#define RMC_MIN(x,y) ((x)<(y)?(x):(y))

void test_rmc_proto(int publisher,
                    char* mcast_group_addr,
                    char* mcast_if_addr,
                    char* listen_if_addr,
                    int mcast_port,
                    int listen_port)
{
    rmc_context_t* ctx1 = 0;
    rmc_context_t* ctx2 = 0;
    int res = 0;
    int send_sock = 0;
    int send_ind = 0;
    int rec_sock = 0;
    int rec_ind = 0;
    sub_packet_t* pack = 0;
    int epollfd = -1;
    struct epoll_event ev, events[RMC_MAX_CONNECTIONS];
    pid_t sub_pid = 0;
    user_data_t ud = { .u64 = 0 };
    int mode = 0;
    char buf[16];
    signal(SIGHUP, SIG_IGN);

    // Create child process that will act as subscriber.
    if (publisher)
        mode = PUBLISH;
    else
        mode = SUBSCRIBE;

    epollfd = epoll_create1(0);

    if (epollfd == -1) {
        perror("epoll_create1");
        exit(255);
    }

    ctx1 = malloc(sizeof(rmc_context_t));
    ctx2 = malloc(sizeof(rmc_context_t));

    rmc_init_context(ctx1,
                     mcast_group_addr, mcast_if_addr, listen_if_addr, mcast_port, listen_port,
                     (user_data_t) { .i32 = epollfd },
                     poll_add, poll_modify, poll_remove, 0, 0);

    rmc_init_context(ctx2,
                     mcast_group_addr, mcast_if_addr, listen_if_addr, mcast_port, listen_port + 1,
                     (user_data_t) { .i32 = epollfd },
                     poll_add, poll_modify, poll_remove, 0, 0);
    

    _test("1.1", rmc_activate_context(ctx1));
    _test("1.2", rmc_activate_context(ctx2));

    printf("context: ctx1[%.9X] ctx2[%.9X]\n", rmc_context_id(ctx1), rmc_context_id(ctx2));

    rmc_queue_packet(ctx1, "p1", 2);

    for (;;) {
        usec_timestamp_t tout = 0;
        int poll_tout = 0;
        int poll_tout1 = -1;
        int poll_tout2 = -1;
        int nfds = 0;

        // Get the next timeout from ctx11
        // If we get ENODATA back, it means that we have no timeouts queued.
        if (rmc_get_next_timeout(ctx1, &tout) != ENODATA) 
            poll_tout1 = tout;

        if (rmc_get_next_timeout(ctx2, &tout) != ENODATA) 
            poll_tout2 = tout;

        poll_tout = RMC_MIN((poll_tout1 == -1)?poll_tout2:poll_tout1, (poll_tout2 == -1)?poll_tout1:poll_tout2);
        
        nfds = epoll_wait(epollfd, events, RMC_MAX_CONNECTIONS, poll_tout);
        if (nfds == -1) {
            perror("epoll_wait");
            exit(255);
        }

        // Timeout
        if (nfds == 0) {
            printf("poll_wait(): timeout\n");
            rmc_process_timeout(ctx1);
            rmc_process_timeout(ctx2);
            continue;
        }
        printf("poll_wait(): %d results\n", nfds);
        while(nfds--) {
            printf("  poll_wait(%s)%s%s%s\n",
                   _index(events[nfds].data.u32, buf),
                   ((events[nfds].events & EPOLLIN)?" read":""),
                   ((events[nfds].events & EPOLLOUT)?" write":""),
                   ((events[nfds].events & EPOLLHUP)?" disconnect":""));

            if (events[nfds].events & EPOLLIN) {
                if (!(res = rmc_read(ctx1, events[nfds].data.u32)) && events[nfds].data.u32 != RMC_LISTEN_INDEX) {
                    pack = rmc_get_next_ready_packet(ctx1);
                    if (!pack) {
                        printf("RMC protocol test 3.1: No packet received\n");
                        exit(255);
                    }

                    if (memcmp(pack->payload, "p1", pack->payload_len)) {
                        printf("RMC protocol test 3.2: Payload differ\n");
                        exit(255);
                    }
                    puts("payload ok");
                }
                if (res && res != ELOOP) {
                    printf("RMC protocol test 3.2: rmc_read() returned %s\n", strerror(res));
                    exit(255);
                }
            }

            if (events[nfds].events & EPOLLOUT) {
                rmc_write(ctx1, events[nfds].data.u32);
            }

            if (events[nfds].events & EPOLLHUP) {
                rmc_close_tcp(ctx1, events[nfds].data.u32);
            }
        }
    }
}
