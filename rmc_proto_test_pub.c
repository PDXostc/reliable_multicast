// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "rmc_proto_test_common.h"
#include <stdlib.h>
#include "rmc_log.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>



// Maximum number of subscribers an rmc_pub_context_t can have.
#define RMC_MAX_CONNECTIONS 16

__attribute__ ((unused))
static uint8_t _test_print_pending(pub_packet_node_t* node, void* dt)
{
    pub_packet_t* pack = (pub_packet_t*) node->data;
    int indent = (int) (uint64_t) dt;

    RMC_LOG_COMMENT("%*cPacket          %p", indent*2, ' ', pack);
    RMC_LOG_COMMENT("%*c  PID             %lu", indent*2, ' ', pack->pid);
    RMC_LOG_COMMENT("%*c  Sent timestamp  %ld", indent*2, ' ', pack->send_ts);
    RMC_LOG_COMMENT("%*c  Reference count %d", indent*2, ' ', pack->ref_count);
    RMC_LOG_COMMENT("%*c  Parent node     %p", indent*2, ' ', pack->parent_node);
    RMC_LOG_COMMENT("%*c  Payload Length  %d", indent*2, ' ', pack->payload_len);
    RMC_LOG_COMMENT("%*c  Payload         %s", indent*2, ' ', (char*) pack->payload);
    RMC_LOG_COMMENT("");

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

    case RMC_NIL_INDEX:
        return -1;

    default:
        return ctx->conn_vec.connections[index].descriptor;

    }
}

static int process_events(rmc_pub_context_t* ctx, int epollfd, usec_timestamp_t timeout)
{
    struct epoll_event events[rmc_pub_get_max_subscriber_count(ctx)];
    int nfds = 0;

    if (timeout != -1) {
        timeout -= rmc_usec_monotonic_timestamp();
        if (timeout < 0)
            timeout = 0;
    }


    nfds = epoll_wait(epollfd, events,
                      rmc_pub_get_max_subscriber_count(ctx),
                      (timeout == -1)?-1:((timeout / 1000) + 1));
    if (nfds == -1) {
        RMC_LOG_FATAL("epoll_wait");
        exit(255);
    }

    // Timeout
    if (nfds == 0)
        return ETIME;

    while(nfds--) {
        int res = 0;
        uint8_t op_res = 0;
        rmc_index_t c_ind = (rmc_index_t) events[nfds].data.u32;

        RMC_LOG_INDEX_DEBUG(c_ind,
                            "pub_poll_wait(%d)%s%s%s",
                            _descriptor(ctx, c_ind),
                            ((events[nfds].events & EPOLLIN)?" read":""),
                            ((events[nfds].events & EPOLLOUT)?" write":""),
                            ((events[nfds].events & EPOLLHUP)?" disconnect":""));


        if (events[nfds].events & EPOLLIN) {
            errno = 0;
            res = rmc_pub_read(ctx, c_ind, &op_res);
            // Did we read a loopback message we sent ourselves?

            RMC_LOG_INDEX_DEBUG(c_ind,
                                "%s:%s", _op_res_string(op_res), strerror(res));
        }

        if (events[nfds].events & EPOLLOUT) {
            res = rmc_pub_write(ctx, c_ind, &op_res);
            if (res != 0 && res != EAGAIN && res != ENODATA)
                rmc_pub_close_connection(ctx, c_ind);
        }
    }

    return 0;
}


void queue_test_data(rmc_pub_context_t* ctx, uint8_t* payload, int payload_len, int drop_flag)
{
    int res = 0;
    res = rmc_pub_queue_packet(ctx, memcpy(malloc(payload_len), payload, payload_len), payload_len, 0);

    if (res) {
        RMC_LOG_FATAL("payload_len[%d]: %s",  payload_len, strerror(res));
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
                                         RMC_LOG_DEBUG("Dropping packet [%lu] as specified", pack->pid);
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
                        rmc_node_id_t node_id,
                        uint64_t count, // Number of signals to send
                        int expected_subscriber_count,
                        int seed,
                        usec_timestamp_t send_interval, //usec
                        int jitter, // usec
                        float drop_rate)
{
    rmc_pub_context_t* ctx = 0;
    int res = 0;
    int epollfd = -1;
    uint64_t signal_ind = 0;
    uint64_t packet_ind = 0;
    uint8_t *conn_vec_mem = 0;
    int subscriber_count = 0;
    usec_timestamp_t current_ts = 0;



    epollfd = epoll_create1(0);

    if (epollfd == -1) {
        perror("epoll_create1");
        exit(255);
    }

    ctx = malloc(sizeof(rmc_pub_context_t));
    conn_vec_mem = malloc(sizeof(rmc_connection_t)*RMC_MAX_CONNECTIONS);
    memset(conn_vec_mem, 0, sizeof(rmc_connection_t)*RMC_MAX_CONNECTIONS);

    rmc_pub_init_context(ctx,
                         0, // Random node id
                         mcast_group_addr, mcast_port,
                         mcast_if_addr,
                         listen_if_addr, listen_port,
                         (user_data_t) { .i32 = epollfd },
                         poll_add, poll_modify, poll_remove,
                         conn_vec_mem,
                         RMC_MAX_CONNECTIONS,
                         lambda(void, (void* pl, payload_len_t len, user_data_t dt) { free(pl); }));


    rmc_pub_set_subscriber_connect_callback(ctx,
                                            lambda(uint8_t, (rmc_pub_context_t*ctx,
                                                             uint32_t remote_addr,
                                                             in_port_t remote_port) {
                                                       char* addr_str = inet_ntoa( (struct in_addr) { .s_addr = htonl( remote_addr) });
                                                       RMC_LOG_INFO("Subscriber [%s:%d] connected",
                                                                    addr_str,
                                                                    remote_port);
                                                       if (!subscriber_count)
                                                           rmc_log_set_start_time();

                                                       subscriber_count++;
                                                       return 1;
                                                   }));


    rmc_pub_set_subscriber_disconnect_callback(ctx,
                                               lambda(void, (rmc_pub_context_t*ctx,
                                                             uint32_t remote_addr,
                                                             in_port_t remote_port) {
                                                          char* addr_str = inet_ntoa( (struct in_addr) { .s_addr = htonl( remote_addr) });
                                                          RMC_LOG_INFO("Subscriber [%s:%d] disconnected",
                                                                       addr_str,
                                                                       remote_port);
                                                          subscriber_count--;
                                                          return;
                                                      }));

    // Send an announcement every 0.3 second.
    rmc_pub_set_announce_interval(ctx, 300000);

    _test("rmc_proto_test_pub[%d.%d] activate_context(): %s",
          1, 1,
          rmc_pub_activate_context(ctx));

    _test("rmc_proto_test_pub[%d.%d] set_ttl(): %s",
          1, 1,
          rmc_pub_set_multicast_ttl(ctx, 1));
    RMC_LOG_INFO("context: ctx[%.9X] mcast_addr[%s] mcast_port[%d]",
                 rmc_pub_node_id(ctx), mcast_group_addr, mcast_port);

    puts("Publisher ready. Run ./rmc_text -S in another window to setup a subscriber.");
    // Wait for the correct number of subscribers to connect before we start sending.
    while(subscriber_count < expected_subscriber_count) {
        usec_timestamp_t event_tout = 0;

        rmc_pub_timeout_get_next(ctx, &event_tout);
        if (process_events(ctx, epollfd, event_tout) == ETIME)
            rmc_pub_timeout_process(ctx);
    }

    // Turn off announcement sending.
    rmc_pub_set_announce_interval(ctx, 0);

    // Seed with a predefined value, allowing us to generate the exact same random sequence
    // every time for packet drops, etc.
    srand(seed);

    signal_ind = 1;
    packet_ind = 0;

    while(signal_ind <= count) {
        uint8_t payload[RMC_MAX_PAYLOAD];
        int payload_len = 0;
        int start_signal_ind = signal_ind;
        float rnd = (float) (rand() % 1000000);
        int drop_flag = 0;
        usec_timestamp_t tout = 0;


        // Fill single packet payload with as many signals as we can
        while(signal_ind <= count && payload_len + sizeof(signal_t) <= RMC_MAX_PAYLOAD) {
            *((signal_t*) (payload + payload_len)) = (signal_t) {
                .node_id = node_id,
                .signal_id = signal_ind,
                .max_signal_id = count,
                .filler = 0
            };

            payload_len += sizeof(signal_t);
            ++signal_ind;
        }

        current_ts = rmc_usec_monotonic_timestamp();        // Check if we are to drop the packet.

        if (rnd / 1000000.0 < drop_rate)
            drop_flag = 1;

        // Check what the wait should be after we sent the packet until we send the next.

        tout = current_ts + send_interval;
        if (jitter > 0)
             tout += (rand() % jitter) * 2 - jitter;

        queue_test_data(ctx, payload, payload_len, drop_flag);
        packet_ind++;
        if (drop_flag)
            RMC_LOG_INFO("dropped packet [%lu]", packet_ind);

        RMC_LOG_DEBUG("packet[%d] signal[%d-%d] drop[%c] wait[%ld]",
                      packet_ind, start_signal_ind, signal_ind, drop_flag?'x':' ', tout-current_ts);

        // Make sure we run the loop at least one.
        if (current_ts > tout)
            current_ts = tout;

        //
        // Process events until it is time to send the next packet.
        //
        while(current_ts < tout || rmc_pub_queue_length(ctx) > 100 ) {
            usec_timestamp_t event_tout = 0;

            rmc_pub_timeout_get_next(ctx, &event_tout);

            if (event_tout == -1 || event_tout > tout)
                event_tout = tout;

            if ((res = process_events(ctx, epollfd, event_tout)) == ETIME)
                rmc_pub_timeout_process(ctx);

            current_ts = rmc_usec_monotonic_timestamp();
        }

        process_events(ctx, epollfd, 0);
        rmc_pub_timeout_process(ctx);

        RMC_LOG_COMMENT("queued packets[%d] inflight[%d]",
                        pub_packet_list_size(&ctx->pub_ctx.queued),
                        pub_packet_list_size(&ctx->pub_ctx.inflight));
    }


    // Continue to process events until subscriber count reaches zero.

    // Disable announce.
    rmc_pub_set_announce_interval(ctx, 0);

    RMC_LOG_INFO("All packets queued");

    while(subscriber_count > 0) {
        usec_timestamp_t tout = 0;
        usec_timestamp_t current_ts = rmc_usec_monotonic_timestamp();

        rmc_pub_timeout_get_next(ctx, &tout);
        // Process all timeouts
        while(tout != -1 && tout < current_ts) {
            rmc_pub_timeout_process(ctx);
            rmc_pub_timeout_get_next(ctx, &tout);
            process_events(ctx, epollfd, tout);
        }


        RMC_LOG_COMMENT("queued packets[%d] inflight[%d]",
                        pub_packet_list_size(&ctx->pub_ctx.queued),
                        pub_packet_list_size(&ctx->pub_ctx.inflight));

        process_events(ctx, epollfd, tout);
    }

    rmc_pub_deactivate_context(ctx);

    RMC_LOG_INFO("Done");

    RMC_LOG_INFO("TO TEST: Publishers that repeatedly connects and disconnects");
    RMC_LOG_INFO("TO TEST: Subscribers that repeatedly connects and disconnects");
    exit(0);
}
