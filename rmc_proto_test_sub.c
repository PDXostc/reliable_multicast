// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "rmc_proto_test_common.h"

static void process_incoming_data(rmc_context_t* ctx, sub_packet_t* pack, rmc_test_data_t* td, int ind)
{

    _test("rmc_proto_test_sub[%d.%d] process_incoming_data(): %s", 3, 1, pack?0:ENODATA);
    if (pack->pid != td->pid) {
        printf("rmc_proto_test_sub[3.2] ind[%d] incoming pid[%lu] differs from expected pid [%lu]. payload[%s]\n",
               ind, pack->pid, td->pid, (char*) pack->payload);
        exit(255);
    }

    if (strcmp((char*) pack->payload, td->payload)) {
        printf("rmc_proto_test_sub[3.3] ind[%d] pid[%lu] incoming data[%s] differs from expected [%s]\n",
               ind, pack->pid, (char*) pack->payload, td->payload);
        exit(255);
    }
    printf("rmc_proto_test_sub:process_incoming_data() ind[%d] pid[%lu] payload[%s]: ok\n",
           ind, pack->pid, (char*) pack->payload);
    
    if (!strcmp(pack->payload, "exit")) {
        puts("Got exit trigger from publisher");
        // Get the final ack out
        rmc_write(ctx, rmc_sub_packet_connection(pack));
        exit(0);
    }
        
    rmc_packet_dispatched(ctx, pack);
    free(pack->payload);
}

void* sub_alloc(payload_len_t payload_len,
                user_data_t user_data)
{
    puts("sub_alloc(): called");
}
    


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
    int ind = 0;
    static rmc_test_data_t td[] = {
        // First packet will be dropped since it is used to trigger a
        // ack socket setup.
        { "p1", 2, 0 },
        { "p2", 3, 0 },
        { "p3", 4, 0 },
        { "exit", 5, 0 }
    };

    signal(SIGHUP, SIG_IGN);

    epollfd = epoll_create1(0);

    if (epollfd == -1) {
        perror("epoll_create1");
        exit(255);
    }

    ctx = malloc(sizeof(rmc_context_t));

    rmc_init_context(ctx,
                     mcast_group_addr,
                     mcast_if_addr,
                     listen_if_addr,
                     mcast_port,
                     listen_port,
                     (user_data_t) { .i32 = epollfd },
                     poll_add, poll_modify, poll_remove,
                     0, lambda(void, (void* pl, payload_len_t len, user_data_t dt) {}));

    _test("rmc_proto_test_sub[%d.%d] activate_context(): %s",
          1, 1,
          rmc_activate_context(ctx));

    printf("rmc_proto_test_sub: context: ctx[%.9X]\n", rmc_context_id(ctx));


    while(ind < sizeof(td) / sizeof(td[0])) {
        sub_packet_t* pack = 0;
        process_events(ctx, epollfd, -1, 3, &ind);
        pack = rmc_get_next_dispatch_ready(ctx);
        if (!pack) {
            continue;
        }
        process_incoming_data(ctx, pack, &td[ind], ind);
        ++ind;
    }
    puts("Done");
}
