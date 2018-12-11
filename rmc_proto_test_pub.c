// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "rmc_proto_test_common.h"
#include <stdlib.h>


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
                       rmc_index_t index)
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

static int process_events(rmc_pub_context_t* ctx, int epollfd, usec_timestamp_t timeout, int major)
{
    struct epoll_event events[RMC_MAX_CONNECTIONS];
    char buf[16];
    int nfds = 0;

    if (timeout != -1) {
        timeout -= rmc_usec_monotonic_timestamp();
        if (timeout < 0)
            timeout = 0;
    }
            

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
        rmc_index_t c_ind = events[nfds].data.u32;

//        printf("pub_poll_wait(%s:%d)%s%s%s\n",
//               _index(c_ind, buf), _descriptor(ctx, c_ind),
//             ((events[nfds].events & EPOLLIN)?" read":""),
//               ((events[nfds].events & EPOLLOUT)?" write":""),
//               ((events[nfds].events & EPOLLHUP)?" disconnect":""));

        // Figure out what to do.
        if (events[nfds].events & EPOLLHUP) {
            puts("POLLHUP");
            _test("rmc_proto_test[%d.%d] process_events():rmc_close_tcp(): %s\n",
                  major, 11, rmc_pub_close_connection(ctx, c_ind));
            continue;
        }

        if (events[nfds].events & EPOLLIN) {
            errno = 0;
            res = rmc_pub_read(ctx, c_ind, &op_res);
            // Did we read a loopback message we sent ourselves?
//            printf("process_events(%s):%s\n", _op_res_string(op_res), strerror(res));
            if (res == EAGAIN)
                continue;       

            _test("rmc_proto_test[%d.%d] process_events():rmc_read(): %s\n", major, 1, res);
                
            // If this was a connection call processed, we can continue.
            if (op_res == RMC_READ_ACCEPT)
                continue;

        }

        if (events[nfds].events & EPOLLOUT) {
            _test("rmc_proto_test[%d.%d] process_events():rmc_write(): %s\n",
                  major, 10,
                  rmc_pub_write(ctx, c_ind, &op_res));
            
//            printf("op_res: %s\n", _op_res_string(op_res));
        }
    }

    return 0;
}


void queue_test_data(rmc_pub_context_t* ctx, char* buf, int drop_flag)
{
    pub_packet_node *node = 0;
    int res = 0;
    res = rmc_pub_queue_packet(ctx, memcpy(malloc(strlen(buf+1)), buf, strlen(buf)+1), strlen(buf)+1, 0);

    if (res) {
        printf("queue_test_data(payload[%s]: %s",
               buf, strerror(res));
        exit(255);
    }

    // Patch node with the correct pid.
    // Find the correct payload and update its pid
    /* TO BE REINTRODUCED WHEN WE DO PACKET FLIPPING ON SENDER SIDE
    pub_packet_list_for_each(&ctx->pub_ctx.queued,
                             lambda (uint8_t, (pub_packet_node_t* node, void* dt) {
                                     pub_packet_t *pack = node->data;
                                     if (pack->payload_len == strlen(td->payload) + 1 &&
                                         !memcmp(pack->payload, td->payload, pack->payload_len)) {
                                         pack->pid = td->pid;
                                         // If we are to drop this packet, mark it as falsely sent.
                                         if (drop_flag) { 
                                             printf("Dropping packet [%lu] as specified\n", pack->pid);
                                             pub_packet_sent(&ctx->pub_ctx, pack, rmc_usec_monotonic_timestamp());
                                         }
                                         return 0;
                                     }
                                     return 1;
                                 }), 0);
    */

}



void test_rmc_proto_pub(char* mcast_group_addr,
                        char* mcast_if_addr,
                        char* listen_if_addr,
                        int mcast_port,
                        int listen_port,
                        rmc_context_id_t node_id,
                        uint64_t count,
                        int expected_subscriber_count,
                        int seed,
                        usec_timestamp_t send_interval, //usec
                        int jitter, // usec
                        float drop_rate)
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
    uint64_t ind = 0;
    usec_timestamp_t t_out = 0;
    uint8_t *conn_vec_mem = 0;
    char buf[128];
    int subscriber_count = 0;
    usec_timestamp_t exit_ts = 0;
    usec_timestamp_t current_ts = 0;
    packet_id_t debug_output_pid = 0;
    int busy = 0;

    uint32_t queued_packets = 0;
    uint32_t send_buf_len = 0;
    uint32_t ack_count = 0;

    signal(SIGHUP, SIG_IGN);

    epollfd = epoll_create1(0);

    if (epollfd == -1) {
        perror("epoll_create1");
        exit(255);
    }

    ctx = malloc(sizeof(rmc_pub_context_t));
    conn_vec_mem = malloc(sizeof(rmc_connection_t)*RMC_MAX_CONNECTIONS);
    memset(conn_vec_mem, 0, sizeof(rmc_connection_t)*RMC_MAX_CONNECTIONS);

    rmc_pub_init_context(ctx,
                         0, // Random context id
                         mcast_group_addr, mcast_port,
                         listen_if_addr, listen_port,
                         (user_data_t) { .i32 = epollfd },
                         poll_add, poll_modify, poll_remove,
                         conn_vec_mem,
                         RMC_MAX_CONNECTIONS,
                         lambda(void, (void* pl, payload_len_t len, user_data_t dt) { free(pl); }));


    rmc_pub_set_subscriber_connect_callback(ctx,
                                            lambda(uint8_t, (rmc_pub_context_t*ctx,
                                                             char* remote_addr,
                                                             in_port_t remote_port) {
                                                       printf("Subscriber [%s:%d] connected\n", remote_addr, remote_port); 
                                                       subscriber_count++;
                                                       return 1;
                                                   }));


    rmc_pub_set_subscriber_disconnect_callback(ctx,
                                               lambda(void, (rmc_pub_context_t*ctx,
                                                             char* remote_addr,
                                                             in_port_t remote_port) {
                                                          printf("Subscriber %s:%d disconnected\n", remote_addr, remote_port);
                                                          subscriber_count--;
                                                          return;
                                                      }));

    // Send an announcement every 0.3 second.
    rmc_pub_set_announce_interval(ctx, 300000);

    _test("rmc_proto_test_pub[%d.%d] activate_context(): %s",
          1, 1,
          rmc_pub_activate_context(ctx));

    printf("rmc_proto_test_pub: context: ctx[%.9X] mcast_addr[%s] mcast_port[%d] \n",
           rmc_pub_context_id(ctx), mcast_group_addr, mcast_port);

    // Wait for the correct number of subscribers to connect before we start sending.
    while(subscriber_count < expected_subscriber_count) {
        usec_timestamp_t event_tout = 0;

        rmc_pub_timeout_get_next(ctx, &event_tout);


        if (process_events(ctx, epollfd, event_tout, 2) == ETIME) 
            rmc_pub_timeout_process(ctx);
    }


    // Seed with a predefined value, allowing us to generate the exact same random sequence
    // every time for packet drops, etc.
    srand(seed);
    debug_output_pid = 1;
    for(ind = 1; ind <= count; ++ind) {
        float rnd = (float) (rand() % 1000000);
        int drop_flag = 0;
        usec_timestamp_t tout = 0;

        current_ts = rmc_usec_monotonic_timestamp();        // Check if we are to drop the packet.
        if (rnd / 1000000.0 < drop_rate)  
            drop_flag = 1;

        // Check what the wait should be after we sent the packet until we send the next.

        tout = current_ts + send_interval;
        if (jitter > 0) 
             tout += (rand() % jitter) * 2 - jitter;
        else

        sprintf(buf, "%u:%lu:%lu", node_id, ind, count);
        queue_test_data(ctx, buf, drop_flag);

        if (drop_flag) 
            printf("dropped packet [%lu]\n", ind);

        if (ind % 1000 == 0) {
            printf("queued packet [%lu-%lu]\n", debug_output_pid, ind);
            debug_output_pid = ind + 1;
        }

        printf("rmc_proto_test_pub: queue_test_data(%s): drop[%c] wait[%ld]\n", buf, drop_flag?'x':' ', tout-current_ts);

        // Make sure we run the loop at least one.
        if (current_ts > tout)
            current_ts = tout;

        //
        // Process events until it is time to send the next packet.
        //
        while(current_ts < tout) {
            usec_timestamp_t event_tout = 0;

            puts("Doing it");
            rmc_pub_timeout_get_next(ctx, &event_tout);

            if (event_tout == -1 || event_tout > tout)
                event_tout = tout;
            
            if ((res = process_events(ctx, epollfd, event_tout, 2)) == ETIME) 
                rmc_pub_timeout_process(ctx);
 
            current_ts = rmc_usec_monotonic_timestamp();
        }  
    }

    puts("Shutting down");
    

    // Disable announce.
    rmc_pub_set_announce_interval(ctx, 0);
    
    busy = rmc_pub_context_get_pending(ctx, &queued_packets, &send_buf_len, &ack_count);
    printf("busy init: queued_packets[%u] send_buf_len[%u] ack_count[%u] -> %s\n",
           queued_packets, send_buf_len, ack_count, (busy==EBUSY)?"busy":"not busy");
    while(busy == EBUSY) {
        usec_timestamp_t tout = 0;
        usec_timestamp_t current_ts = rmc_usec_monotonic_timestamp();
        

        rmc_pub_timeout_get_next(ctx, &tout);
        if (tout != -1)
            printf("tout[%ld]\n", tout - current_ts);
        else
            printf("tout[infinite]");

        printf("queued[%d] inflight[%d]\n",
               pub_packet_list_size(&ctx->pub_ctx.queued),
               pub_packet_list_size(&ctx->pub_ctx.inflight));

               

        // Even if we have infinite timeout, we will process events
        // since we may have pending data that we need to write when
        // we get EPOLLOUT from epoll()
        //
        if ((res = process_events(ctx, epollfd, tout, 2)) == ETIME || tout < current_ts)  {
            puts("Processing timeout");
            rmc_pub_timeout_process(ctx);
        }
        busy = rmc_pub_context_get_pending(ctx, &queued_packets, &send_buf_len, &ack_count);
        printf("busy: queued_packets[%u] send_buf_len[%u] ack_count[%u] -> %s\n",
               queued_packets, send_buf_len, ack_count, (busy==EBUSY)?"busy":"not busy");

    }

        busy = rmc_pub_context_get_pending(ctx, &queued_packets, &send_buf_len, &ack_count);
        printf("exit busy: queued_packets[%u] send_buf_len[%u] ack_count[%u] -> %s\n",
               queued_packets, send_buf_len, ack_count, (busy==EBUSY)?"busy":"not busy");

    rmc_pub_deactivate_context(ctx);
    puts("Done");

    puts("TO TEST: Multiple publishers. Single subscriber");

    puts("TO TEST: Multiple subscribers. Single publisher");
    puts("TO TEST: Publishers that repeatedly connects and disconnects");
    puts("TO TEST: Subscribers that repeatedly connects and disconnects");
}

