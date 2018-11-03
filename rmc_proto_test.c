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
static char* _index(rmc_poll_index_t index, char* res)
{
    switch(index) {
    case RMC_MULTICAST_INDEX:
        return strcpy(res, "mcast");

        break;

    case RMC_LISTEN_INDEX:
        return strcpy(res, "listen");

        break;

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

void poll_add(rmc_context_t* ctx, rmc_poll_t* poll)
{
    char buf[16];
    int epollfd = rmc_user_data(ctx).i32;
    struct epoll_event ev = {
        .data.u32 = poll->rmc_index,
        .events = EPOLLONESHOT
    };

    if (poll->action & RMC_POLLREAD)
        ev.events |= EPOLLIN;

    if (poll->action & RMC_POLLWRITE)
        ev.events |= EPOLLOUT;

    printf("poll_add(%s)%s%s\n",
           _index(poll->rmc_index, buf),
           ((poll->action & RMC_POLLREAD)?" read":""),
           ((poll->action & RMC_POLLWRITE)?" write":""));

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, poll->descriptor, &ev) == -1) {
        perror("epoll_ctl(add)");
        exit(255);
    }
}

void poll_modify(rmc_context_t* ctx, rmc_poll_t* old_poll, rmc_poll_t* new_poll)
{
    char buf[16];
    int epollfd = rmc_user_data(ctx).i32;
    struct epoll_event ev = {
        .data.u32 = new_poll->rmc_index,
        .events = EPOLLONESHOT
    };

    if (new_poll->action & RMC_POLLREAD)
        ev.events |= EPOLLIN;

    if (new_poll->action & RMC_POLLWRITE)
        ev.events |= EPOLLOUT;

    printf("poll_modify(%s)%s%s\n",
           _index(new_poll->rmc_index, buf),
           ((new_poll->action & RMC_POLLREAD)?" read":""),
           ((new_poll->action & RMC_POLLWRITE)?" write":""));

    if (epoll_ctl(epollfd, EPOLL_CTL_MOD, new_poll->descriptor, &ev) == -1) {
        perror("epoll_ctl(modify)");
        exit(255);
    }
}

void poll_remove(rmc_context_t* ctx, rmc_poll_t* poll)
{
    char buf[16];
    int epollfd = rmc_user_data(ctx).i32;

    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, poll->descriptor, 0) == -1) {
        perror("epoll_ctl(delete)");
        exit(255);
    }
    printf("poll_remove(%s)\n", _index(poll->rmc_index, buf));
}



#define PUBLISH 1
#define SUBSCRIBE 2
void test_rmc_proto(int subs_flag)
{
    rmc_context_t* ctx = 0;
    int res = 0;
    int send_sock = 0;
    int send_ind = 0;
    int rec_sock = 0;
    int rec_ind = 0;
    sub_packet_t* pack = 0;
    int epollfd = -1;
    struct epoll_event ev, events[RMC_MAX_SOCKETS];
    pid_t sub_pid = 0;
    user_data_t ud = { .u64 = 0 };
    int mode = PUBLISH;
    char buf[16];

    signal(SIGHUP, SIG_IGN);

    // Create child process that will act as subscriber.
    if (subs_flag)
        mode = SUBSCRIBE;

    epollfd = epoll_create1(0);

    if (epollfd == -1) {
        perror("epoll_create1");
        exit(255);
    }

    ctx = malloc(sizeof(rmc_context_t));

    rmc_init_context(ctx, "239.0.0.1", 0, 4723, (user_data_t) { .i32 = epollfd },
                     poll_add, poll_modify, poll_remove, 0, 0);
    

    _test("1.1", rmc_activate_context(ctx));

    if (mode == PUBLISH)
        rmc_queue_packet(ctx, "p1", 2);

    for (;;) {
        usec_timestamp_t tout = 0;
        int poll_tout = 0;
        int nfds = 0;

        // Get the next timeout from ctx1
        // If we get ENODATA back, it means that we have no timeouts queued.
        if (rmc_get_next_timeout(ctx, &tout) == ENODATA) 
            poll_tout = -1;
        else
            poll_tout = tout;

        nfds = epoll_wait(epollfd, events, RMC_MAX_SOCKETS, -1);
        if (nfds == -1) {
            perror("epoll_wait");
            exit(255);
        }

        // Timeout
        if (nfds == 0) {
            printf("poll_wait(): timeout\n");
            rmc_process_timeout(ctx);
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
                rmc_read(ctx, events[nfds].data.u32);

                pack = rmc_get_next_ready_packet(ctx);
                if (!pack) {
                    printf("RMC protocol test 3.1: No packet received\n");
                    exit(255);
                }

                if (memcmp(pack->payload, "p1", pack->payload_len)) {
                    printf("RMC protocol test 3.2: Payload differ\n");
                    exit(255);
                }
            }

            if (events[nfds].events & EPOLLOUT) {
                rmc_write(ctx, events[nfds].data.u32);
            }

            if (events[nfds].events & EPOLLHUP) {
                rmc_close_tcp(ctx, events[nfds].data.u32);
            }
        }
    }
}
