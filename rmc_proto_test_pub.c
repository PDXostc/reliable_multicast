// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "rmc_proto_test_common.h"


void queue_test_data(rmc_context_t* ctx, rmc_test_data_t* td_arr, int td_arr_ind)
{
    pub_packet_node *node = 0;
    int res = 0;
    res = rmc_queue_packet(ctx, td_arr[td_arr_ind].payload, strlen(td_arr[td_arr_ind].payload));

    if (res) {
        printf("queue_test_data(payload[%s], pid[%lu]): %s",
               td_arr[td_arr_ind].payload,
               td_arr[td_arr_ind].pid,
               strerror(res));
        exit(255);
    }

    // Patch node with the correct pid.
    pub_packet_list_tail(&ctx->pub_ctx.queued)->data->pid = td_arr[td_arr_ind].pid;
}



void test_rmc_proto_pub(char* mcast_group_addr,
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
    int ind = 0;
    static rmc_test_data_t td[] = {
        { "p1", 1 },
        { "p2", 2 },
        { "p3", 3 }
    };

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

    for(ind = 0; ind < sizeof(td) / sizeof(td[0]); ++ind)
        queue_test_data(ctx, td, ind);


    while(process_events(ctx, epollfd, 2) != ETIME)
        ;

}
