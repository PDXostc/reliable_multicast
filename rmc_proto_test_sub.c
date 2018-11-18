// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "rmc_proto_test_common.h"

static void process_incoming_data(rmc_sub_context_t* ctx, sub_packet_t* pack, rmc_test_data_t* td, int ind)
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
    
//    if (!strcmp(pack->payload, "exit")) {
//        puts("Got exit trigger from publisher");
//        // Get the final ack out
//        rmc_packet_dispatched(ctx, pack);
//        rmc_packet_acknowledged(ctx, pack);
//        rmc_write(ctx, rmc_sub_packet_connection(pack), 0);
//        exit(0);
//    }
        
    rmc_sub_packet_dispatched(ctx, pack);
    rmc_sub_packet_acknowledged(ctx, pack);
    free(pack->payload);
}

void* sub_alloc(payload_len_t payload_len,
                user_data_t user_data)
{
    puts("sub_alloc(): called");
}


static int process_events(rmc_sub_context_t* ctx, int epollfd, usec_timestamp_t timeout, int major, int* tick_ind)
{
    struct epoll_event events[RMC_MAX_CONNECTIONS];
    char buf[16];
    int nfds = 0;

    *tick_ind = 0;

    nfds = epoll_wait(epollfd, events, RMC_MAX_CONNECTIONS, (timeout == -1)?-1:(timeout / 1000));
    if (nfds == -1) {
        perror("epoll_wait");
        exit(255);
    }

    // Timeout
    if (nfds == 0) 
        return ETIME;


    // printf("poll_wait(): %d results\n", nfds);

    while(nfds--) {
        int res = 0;
        uint8_t op_res = 0;
        rmc_connection_index_t c_ind = events[nfds].data.u32;

//        printf("poll_wait(%s:%d)%s%s%s\n",
//               _index(c_ind, buf), _descriptor(ctx, c_ind),
//               ((events[nfds].events & EPOLLIN)?" read":""),
//
//               ((events[nfds].events & EPOLLOUT)?" write":""),
//               ((events[nfds].events & EPOLLHUP)?" disconnect":""));

        // Figure out what to do.
        if (events[nfds].events & EPOLLHUP) {
            _test("rmc_proto_test[%d.%d] process_events():rmc_close_tcp(): %s\n",
                  major, 11, _rmc_conn_close_connection(&ctx->conn_vec, c_ind));
            continue;
        }

        if (events[nfds].events & EPOLLIN) {
            errno = 0;
            res = rmc_sub_read(ctx, c_ind, &op_res);
            // Did we read a loopback message we sent ourselves?
            printf("process_events(%s):%s\n", _op_res_string(op_res), strerror(res));
            if (res == ELOOP)
                continue;       

            _test("rmc_proto_test[%d.%d] process_events():rmc_read(): %s\n", major, 1, res);
                
            // If this was a connection call processed, we can continue.
            if (op_res == RMC_READ_ACCEPT)
                continue;

            if (op_res == RMC_READ_MULTICAST)
                *tick_ind = 1;
        }

        if (events[nfds].events & EPOLLOUT) {
            _test("rmc_proto_test[%d.%d] process_events():rmc_write(): %s\n",
                  major, 10,
                  rmc_sub_write(ctx, c_ind, &op_res));

            printf("op_res: %s\n", _op_res_string(op_res));

            if (op_res == RMC_WRITE_MULTICAST)
                *tick_ind = 1;
        }
    }

    return 0;
}



void test_rmc_proto_sub(char* mcast_group_addr,
                        char* mcast_if_addr,
                        char* control_addr,
                        int mcast_port,
                        int control_port)
{
    rmc_sub_context_t* ctx = 0;
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
    usec_timestamp_t t_out = 0;
    uint8_t *conn_vec_mem = 0;

    static rmc_test_data_t td[] = {
        // First packet sent by publisher, 'ping', will be dropped
        // since it is used to trigger a ack socket setup.
        { "p1", 2, 0 },
        { "p2", 3, 0 },
        { "p3", 4, 0 },
        { "p4", 5, 0 },
//        { "d1", 6, -1 } // Drop and expect tcp retransmit
    };

    signal(SIGHUP, SIG_IGN);

    epollfd = epoll_create1(0);

    if (epollfd == -1) {
        perror("epoll_create1");
        exit(255);
    }

    ctx = malloc(sizeof(rmc_sub_context_t));

    conn_vec_mem = malloc(sizeof(rmc_connection_t)*RMC_MAX_CONNECTIONS);

    rmc_sub_init_context(ctx,
                         0, // Assign random context id
                         mcast_group_addr,
                         mcast_if_addr,
                         mcast_port,
                         control_addr,
                         control_port,
                         (user_data_t) { .i32 = epollfd },
                         poll_add, poll_modify, poll_remove,
                         conn_vec_mem, RMC_MAX_CONNECTIONS,
                         lambda(void*, (payload_len_t len, user_data_t dt) { malloc(len);}));

    _test("rmc_proto_test_sub[%d.%d] activate_context(): %s",
          1, 1,
          rmc_sub_activate_context(ctx));

    printf("rmc_proto_test_sub: context: ctx[%.9X]\n", rmc_sub_context_id(ctx));


    while(ind < sizeof(td) / sizeof(td[0])) {
        int tick_ind = 0;
        sub_packet_t* pack = 0;

        rmc_sub_timeout_get_next(ctx, &t_out);

        if (process_events(ctx, epollfd, t_out, 3, &tick_ind) == ETIME) {
            rmc_sub_timeout_process(ctx);
            continue;
        }

        // Process as many packets as possible.
        while((pack = rmc_sub_get_next_dispatch_ready(ctx))) {
            process_incoming_data(ctx, pack, &td[ind], ind);
            if (tick_ind)
                ++ind;
        }
    }
        
    // Process timed out acks that need to be sent.
    rmc_sub_timeout_get_next(ctx, &t_out);

    while(t_out != -1) {
        int tick_ind = 0;
        if (process_events(ctx, epollfd, t_out, 2, &tick_ind) == ETIME)
            rmc_sub_timeout_process(ctx);

        rmc_sub_timeout_get_next(ctx, &t_out);
    }

    puts("Done");
}
