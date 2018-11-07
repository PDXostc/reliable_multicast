// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "rmc_proto_test_common.h"

void test_rmc_proto_sub(char* mcast_group_addr,
                        char* mcast_if_addr,
                        char* listen_if_addr,
                        int mcast_port,
                        int listen_port)
{
    rmc_context_t* ctx = 0;
    int res = 0;
    int send_sock = 0;
    int send_ind = 0;
    int rec_sock = 0;
    int rec_ind = 0;
    int epollfd = -1;
    pid_t sub_pid = 0;
    user_data_t ud = { .u64 = 0 };
    int mode = 0;

    signal(SIGHUP, SIG_IGN);


    epollfd = epoll_create1(0);

    if (epollfd == -1) {
        perror("epoll_create1");
        exit(255);
    }

    ctx = malloc(sizeof(rmc_context_t));

    rmc_init_context(ctx,
                     mcast_group_addr, mcast_if_addr, listen_if_addr, mcast_port, listen_port,
                     (user_data_t) { .i32 = epollfd },
                     poll_add, poll_modify, poll_remove, 0, 0);


    _test("rmc_proto_test[%d.%d] activate_context(): %s",
          1, 1,
          rmc_activate_context(ctx));

    printf("context: ctx[%.9X]\n", rmc_context_id(ctx));

    _test("rmc_proto_test[%d.%d] rmc_queue_event(): %s",
          1, 1,
          rmc_queue_packet(ctx, "p1", 2));

    while(1)
        process_events(ctx, epollfd, 2);

}
