// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "rmc_proto_test_common.h"

static uint8_t _test_print_pending(pub_packet_node_t* node, void* dt)
{
    pub_packet_t* pack = (pub_packet_t*) node->data;
    int indent = (int) (uint64_t) dt;

    printf("%*cPending Packet  %p\n", indent*2, ' ', pack);
    printf("%*c  PID             %lu\n", indent*2, ' ', pack->pid);
    printf("%*c  Sent timestamp  %lu\n", indent*2, ' ', pack->send_ts);
    printf("%*c  Reference count %d\n", indent*2, ' ', pack->ref_count);
    printf("%*c  Parent node     %p\n", indent*2, ' ', pack->parent_node);
    printf("%*c  Payload Length  %d\n", indent*2, ' ', pack->payload_len);
    putchar('\n');
    return 1;
}

void queue_test_data(rmc_context_t* ctx, rmc_test_data_t* td_arr, int td_arr_ind)
{
    pub_packet_node *node = 0;
    int res = 0;
    res = rmc_queue_packet(ctx, td_arr[td_arr_ind].payload, strlen(td_arr[td_arr_ind].payload)+1);

    if (res) {
        printf("queue_test_data(payload[%s], pid[%lu]): %s",
               td_arr[td_arr_ind].payload,
               td_arr[td_arr_ind].pid,
               strerror(res));
        exit(255);
    }

    // Patch node with the correct pid.
//    pub_packet_list_tail(&ctx->pub_ctx.queued)->data->pid = td_arr[td_arr_ind].pid;
    pub_packet_list_for_each(&ctx->pub_ctx.queued, _test_print_pending, (void*) (uint64_t) 1);
    
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
    int countdown = 10;
    static rmc_test_data_t td[] = {
        { "ping", 1, 100 },
        { "p1", 2, 0 },
        { "p2", 3, 0 },
        { "p3", 4, 0 },
        { "exit", 5, 0 },
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
                     poll_add, poll_modify, poll_remove,
                     0, lambda(void, (void* pl, payload_len_t len, user_data_t dt) { }));



    _test("rmc_proto_test_pub[%d.%d] activate_context(): %s",
          1, 1,
          rmc_activate_context(ctx));

    printf("rmc_proto_test_pub: context: ctx[%.9X]\n", rmc_context_id(ctx));

    for(ind = 0; ind < sizeof(td) / sizeof(td[0]); ++ind) {
        usec_timestamp_t now = rmc_usec_monotonic_timestamp();
        usec_timestamp_t wait_until = now + td[ind].msec_wait * 1000;
        usec_timestamp_t t_out = 0;

        queue_test_data(ctx, td, ind);
        
        // Process events until it is time to queue and send the next
        // frame (or quit).
        printf("now[%lu] wait_until[%lu]\n", now, wait_until);
        while(now <= wait_until) {
            t_out = (wait_until - now);
            process_events(ctx, epollfd, t_out, 2, &ind);
            now = rmc_usec_monotonic_timestamp();
        }
    }

    while(countdown--) {
        printf("tick[%d]\n", countdown);
        process_events(ctx, epollfd, 1000000, 2, &ind);
    }
    puts("Done");
}


