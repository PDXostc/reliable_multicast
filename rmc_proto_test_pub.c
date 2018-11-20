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

    printf("%*cPacket          %p\n", indent*2, ' ', pack);
    printf("%*c  PID             %lu\n", indent*2, ' ', pack->pid);
    printf("%*c  Sent timestamp  %ld\n", indent*2, ' ', pack->send_ts);
    printf("%*c  Reference count %d\n", indent*2, ' ', pack->ref_count);
    printf("%*c  Parent node     %p\n", indent*2, ' ', pack->parent_node);
    printf("%*c  Payload Length  %d\n", indent*2, ' ', pack->payload_len);
    printf("%*c  Payload         %s\n", indent*2, ' ', (char*) pack->payload);
    putchar('\n');
    return 1;
}

static int _descriptor(rmc_pub_context_t* ctx,
                       rmc_connection_index_t index)
{
    switch(index) {
    case RMC_MULTICAST_INDEX:
        return ctx->mcast_send_descriptor;

    case RMC_LISTEN_INDEX:
        return ctx->listen_descriptor;

    default:
        return ctx->conn_vec.connections[index].descriptor;

    }
}

static int process_events(rmc_pub_context_t* ctx, int epollfd, usec_timestamp_t timeout, int major, int* tick_ind)
{
    struct epoll_event events[RMC_MAX_CONNECTIONS];
    char buf[16];
    int nfds = 0;

    *tick_ind = 0;

    nfds = epoll_wait(epollfd, events, RMC_MAX_CONNECTIONS, (timeout == -1)?-1:((timeout / 1000) + 1));
    if (nfds == -1) {
        perror("epoll_wait");
        exit(255);
    }

    // Timeout
    if (nfds == 0) 
        return ETIME;

    while(nfds--) {
        int res = 0;
        uint8_t op_res = 0;
        rmc_connection_index_t c_ind = events[nfds].data.u32;

        printf("pub_poll_wait(%s:%d)%s%s%s\n",
               _index(c_ind, buf), _descriptor(ctx, c_ind),
               ((events[nfds].events & EPOLLIN)?" read":""),
               ((events[nfds].events & EPOLLOUT)?" write":""),
               ((events[nfds].events & EPOLLHUP)?" disconnect":""));

        // Figure out what to do.
        if (events[nfds].events & EPOLLHUP) {
            _test("rmc_proto_test[%d.%d] process_events():rmc_close_tcp(): %s\n",
                  major, 11, _rmc_conn_close_connection(&ctx->conn_vec, c_ind));
            continue;
        }

        if (events[nfds].events & EPOLLIN) {
            errno = 0;
            res = rmc_pub_read(ctx, c_ind, &op_res);
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
                  rmc_pub_write(ctx, c_ind, &op_res));
            
            printf("op_res: %s\n", _op_res_string(op_res));

            if (op_res == RMC_WRITE_MULTICAST)
                *tick_ind = 1;
        }
    }

    return 0;
}


void queue_test_data(rmc_pub_context_t* ctx, rmc_test_data_t* td)
{
    pub_packet_node *node = 0;
    int res = 0;
    res = rmc_pub_queue_packet(ctx, td->payload, strlen(td->payload)+1);

    if (res) {
        printf("queue_test_data(payload[%s], pid[%lu]): %s",
               td->payload,
               td->pid,
               strerror(res));
        exit(255);
    }

    // Patch node with the correct pid.
    // Find the correct payload and update its pid
    pub_packet_list_for_each(&ctx->pub_ctx.queued,
                             lambda (uint8_t, (pub_packet_node_t* node, void* dt) {
                                     pub_packet_t *pack = node->data;
                                     if (pack->payload_len == strlen(td->payload) + 1 &&
                                         !memcmp(pack->payload, td->payload, pack->payload_len)) {
                                         pack->pid = td->pid;
                                             return 0;
                                     }
                                     return 1;
                                 }), 0);
}



void test_rmc_proto_pub(char* mcast_group_addr,
                        char* mcast_if_addr,
                        char* listen_if_addr,
                        int mcast_port,
                        int listen_port)
{
    rmc_pub_context_t* ctx = 0;
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
    usec_timestamp_t t_out = 0;
    uint8_t *conn_vec_mem = 0;
    static rmc_test_data_t td[] = { 
        // Wait for 0.01 seconds for return tcp connection coming back in from subscriber
        { "ping", 1, 100000 }, 
        { "p1", 2, 0 },
        { "p3", 4, 0 },
        { "p2", 3, 0 },
        { "p4", 5, 0 }, 
        // Dropped packagte.
        { "d1", 6, 300000 }, // Wait for 1 sec until exiting to process residual event.
        { "exit", 7, 1000000 }, // Wait for 1 sec until exiting to process residual event.
    };


    signal(SIGHUP, SIG_IGN);

    epollfd = epoll_create1(0);

    if (epollfd == -1) {
        perror("epoll_create1");
        exit(255);
    }

    ctx = malloc(sizeof(rmc_pub_context_t));
    conn_vec_mem = malloc(sizeof(rmc_connection_t)*RMC_MAX_CONNECTIONS);

    rmc_pub_init_context(ctx,
                         0, // assign random context id.
                         mcast_group_addr, mcast_port,
                         listen_if_addr, listen_port,
                         (user_data_t) { .i32 = epollfd },
                         poll_add, poll_modify, poll_remove,
                         conn_vec_mem,
                         RMC_MAX_CONNECTIONS,
                         lambda(void, (void* pl, payload_len_t len, user_data_t dt) { }));



    _test("rmc_proto_test_pub[%d.%d] activate_context(): %s",
          1, 1,
          rmc_pub_activate_context(ctx));

    printf("rmc_proto_test_pub: context: ctx[%.9X]\n", rmc_pub_context_id(ctx));

    for(ind = 0; ind < sizeof(td) / sizeof(td[0]); ) {
        usec_timestamp_t now =  rmc_usec_monotonic_timestamp();
        usec_timestamp_t tout =  now + td[ind].wait;
        int tick_ind = 0;

        queue_test_data(ctx, &td[ind]);
        printf("rmc_proto_test_pub: queue_test_data(%ld)\n", td[ind].pid);

        // Make sure we run the loop at least one.
        if (now > tout)
            now = tout;

        tick_ind = 0;
        while(now < tout) {
            usec_timestamp_t event_tout = 0;

            rmc_pub_timeout_get_next(ctx, &event_tout);

            if (event_tout == -1 || event_tout > tout - now)
                event_tout = tout - now;

            if ((res = process_events(ctx, epollfd, event_tout, 2, &tick_ind)) == ETIME) 
                rmc_pub_timeout_process(ctx);

            now = rmc_usec_monotonic_timestamp();
        }        
        ++ind;
        
    }

    puts("Done");
}
