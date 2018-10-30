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

#define MAX_EVENTS 10

void test_rmc_proto(void)
{
    rmc_context_t ctx;
    int res;
    int send_sock = 0;
    int send_ind = 0;
    int rec_sock = 0;
    int rec_ind = 0;
    sub_packet_t* pack;
    int epollfd;
    struct epoll_event ev, events[MAX_EVENTS];

    epollfd = epoll_create1(0);

    if (epollfd == -1) {
        perror("epoll_create1");
        exit(255);
    }

//    ev.events = EPOLLIN;
//    ev.data.u32 = listen_sock;
//    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listen_sock, &ev) == -1) {
//        perror("epoll_ctl: listen_sock");
//        exit(255);
//    }
//
//    for (;;) {
//        nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
//               if (nfds == -1) {
//                   perror("epoll_wait");
//                   exit(EXIT_FAILURE);
//               }
//
//               for (n = 0; n < nfds; ++n) {
//                   if (events[n].data.fd == listen_sock) {
//                       conn_sock = accept(listen_sock,
//                                          (struct sockaddr *) &addr, &addrlen);
//                       if (conn_sock == -1) {
//                           perror("accept");
//                           exit(EXIT_FAILURE);
//                       }
//                       setnonblocking(conn_sock);
//                       ev.events = EPOLLIN | EPOLLET;
//                       ev.data.fd = conn_sock;
//                       if (epoll_ctl(epollfd, EPOLL_CTL_ADD, conn_sock,
//                                   &ev) == -1) {
//                           perror("epoll_ctl: conn_sock");
//                           exit(EXIT_FAILURE);
//                       }
//                   } else {
//                       do_use_fd(events[n].data.fd);
//                   }
//               }
//           }

    rmc_init_context(&ctx, "239.0.0.1", 0, 4723, 0, 0, 0, 0, 0);

    _test("1.1", rmc_activate_context(&ctx));

    rmc_queue_packet(&ctx, "p1", 2);
    rmc_write(&ctx, RMC_MULTICAST_SOCKET_INDEX);
    rmc_read(&ctx, RMC_MULTICAST_SOCKET_INDEX);

    pack = rmc_get_next_ready_packet(&ctx);
    if (!pack) {
        printf("RMC protocol test 3.1: No packet received\n");
        exit(255);
    }

    if (memcmp(pack->payload, "p1", pack->payload_len)) {
        printf("RMC protocol test 3.2: Payload differ\n");
        exit(255);
    }
}
