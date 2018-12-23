// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "rmc_proto_test_common.h"
#include "rmc_log.h"

// Indexed by publisher node_id, as received in the
// payload 
typedef struct {
    enum {
        // We will not process traffic for this node_id.
        // Any traffic received will trigger error.
        RMC_TEST_SUB_INACTIVE = 0,  

        // We expect traffic on this ctx-id (as provided by -e <ctx-id>,
        // But haven't seen any yet.
        RMC_TEST_SUB_NOT_STARTED = 1, 

        // We are in the process of receiving traffic 
        RMC_TEST_SUB_IN_PROGRESS = 2,

        // We have received all expected traffic for the given ctx-id.
        RMC_TEST_SUB_COMPLETED = 3
    } status;    

    uint64_t max_expected;
    uint64_t max_received;
    uint64_t expect_sum;
    uint64_t calc_sum;
    usec_timestamp_t start_ts; // First packet received
    usec_timestamp_t stop_ts; // Last packet received
} sub_expect_t;


static uint8_t _test_print_pending(sub_packet_node_t* node, void* dt)
{

    sub_packet_t* pack = (sub_packet_t*) node->data;
    int indent = (int) (uint64_t) dt;

    printf("%*cPacket          %p\n", indent*2, ' ', pack);
    printf("%*c  PID             %lu\n", indent*2, ' ', pack->pid);
    printf("%*c  Payload Length  %d\n", indent*2, ' ', pack->payload_len);
    putchar('\n');
    return 1;
}


static int _descriptor(rmc_sub_context_t* ctx,
                       rmc_index_t index)
{
    switch(index) {
    case RMC_MULTICAST_INDEX:
        return ctx->mcast_recv_descriptor;

    default:
        return ctx->conn_vec.connections[index].descriptor;

    }
}

static int check_exit_condition( sub_expect_t* expect, int expect_sz)
{
    int ind = expect_sz;

    while(ind--) {
        if (expect[ind].status == RMC_TEST_SUB_NOT_STARTED ||
            expect[ind].status == RMC_TEST_SUB_IN_PROGRESS)
            return 0;
    }
    return 1;
}


static uint8_t announce_cb(struct rmc_sub_context* ctx,
                           char* listen_ip, // "1.2.3.4"
                           in_port_t listen_port,
                           void* payload,
                           payload_len_t payload_len)
{
    RMC_LOG_INFO("Announce detected. Starting tests");

    rmc_log_set_start_time();
    return 1;
}




static int process_incoming_signal(rmc_sub_context_t* ctx,
                                   char* data,
                                   sub_expect_t* expect,
                                   int expect_sz)
                                   
                                 
{
    signal_t *signal = (signal_t*) data;
    rmc_context_id_t node_id = signal->node_id;
    uint64_t max_expected = signal->max_signal_id;
    uint64_t current = signal->signal_id;

    
    // Is context ID within our expetcted range
    if (node_id >= expect_sz) {
        RMC_LOG_FATAL("ContextID [%u] is out of range (0-%d)",
               node_id, expect_sz);
        exit(255);
     }

    // Is this context expected?
    if (expect[node_id].status == RMC_TEST_SUB_INACTIVE) {
        RMC_LOG_FATAL("ContextID [%u] not expected. Use -e %u to setup subscriber expectations.",
               node_id, node_id);
        exit(255);
    }

    // Have we already completed all expected packages here?
    if (expect[node_id].status == RMC_TEST_SUB_COMPLETED) {
        RMC_LOG_FATAL("ContextID [%u] have already processed its [%lu] packets. Got Current[%lu] Max[%lu].",
               node_id, expect[node_id].max_received, current, max_expected);
        exit(255);
    }

    // Check if this is the first packet from an expected source.
    // If so, set things up.
    if (expect[node_id].status == RMC_TEST_SUB_NOT_STARTED) {
        int ind = 0;
        expect[node_id].status = RMC_TEST_SUB_IN_PROGRESS;
        expect[node_id].max_expected = max_expected;
        expect[node_id].max_received = 0; 
        expect[node_id].expect_sum = 0; 
        expect[node_id].calc_sum = 0; 
        expect[node_id].start_ts = rmc_usec_monotonic_timestamp();
        expect[node_id].stop_ts = 0;

        // Calculate sum
        for(ind = 1; ind <= max_expected; ++ind)
            expect[node_id].expect_sum += ind;

        RMC_LOG_INFO("Activate: node_id[%u] current[%lu] max_expected[%lu] expected sum[%lu]",
                     node_id, current, max_expected, expect[node_id].calc_sum);

        // Fall through to the next if statement
    }

    // Check if we are in progress.
    // If so, check that packets are correctly numbrered.

    if (expect[node_id].status == RMC_TEST_SUB_IN_PROGRESS) {

        // Check that max_expected hasn't changed.
        if (max_expected != expect[node_id].max_expected) {
            RMC_LOG_FATAL("ContextID [%u] max_expected changed from [%lu] to [%lu]",
                   node_id, expect[node_id].max_expected, max_expected);
            exit(255);
        }
        
        // Check that packet is consecutive.
        if (current != expect[node_id].max_received + 1) {
            RMC_LOG_FATAL("ContextID [%u] Wanted[%lu] Got[%lu]",
                   node_id, expect[node_id].max_received + 1, current);
            exit(255);
        }

        expect[node_id].max_received = current;
        expect[node_id].calc_sum += current;
        
        // Check if we are complete
        if (current == max_expected) {
            int pack_sec = 0;
            RMC_LOG_INFO("rmc_proto_test_sub(): ContextID [%u] %s**COMPLETE*%s* at[%lu]",
                         node_id, rmc_log_color_green(), rmc_log_color_none(), current);
            
            // Did we see data corruption?
            if (expect[node_id].expect_sum !=  expect[node_id].calc_sum) {
                printf("DATA CORRUPTION! Expected total sum: %lu. Got %lu\n",
                       expect[node_id].expect_sum,
                       expect[node_id].calc_sum);
                exit(0);
            }


            expect[node_id].status = RMC_TEST_SUB_COMPLETED;
            expect[node_id].stop_ts = rmc_usec_monotonic_timestamp();

            pack_sec = (int) expect[node_id].max_received /
                ((double) (expect[node_id].stop_ts - expect[node_id].start_ts) / 1000000.0);

            RMC_LOG_INFO("[%lu] packets in [%lu] msec -> %s%d packets / sec%s",
                         expect[node_id].max_received,
                         (expect[node_id].stop_ts - expect[node_id].start_ts) / 1000,
                         rmc_log_color_green(),
                         pack_sec,
                         rmc_log_color_none());

            // Check if this is the last one out.
            if (check_exit_condition(expect, expect_sz))
                return 0;
        }

        return 1;
    }

    printf("rmc_proto_test_sub(): Eh? expect[%u:%lu:%lu] status[%d]  data[%u:%lu:%lu]\n",
           node_id, expect[node_id].max_received, expect[node_id].max_expected,
           expect[node_id].status,
           node_id, current, max_expected);

    exit(255);
}

static int process_incoming_packet(rmc_sub_context_t* ctx,
                                   sub_packet_t* pack,
                                   sub_expect_t* expect,
                                   int expect_sz)
{
    int pack_ind = 0;


    while(pack_ind < pack->payload_len) {
        if (!process_incoming_signal(ctx, pack->payload + pack_ind, expect, expect_sz))
            return 0;

        pack_ind += sizeof(signal_t);
    }

    // Will free payload
    rmc_sub_packet_dispatched(ctx, pack);
    return 1;
}

static int process_events(rmc_sub_context_t* ctx,
                          int epollfd,
                          usec_timestamp_t timeout_ts)
{
    struct epoll_event events[RMC_MAX_CONNECTIONS];
    char buf[16];
    int nfds = 0;
    usec_timestamp_t current_ts = rmc_usec_monotonic_timestamp();
    
    if (timeout_ts != -1) {
        timeout_ts -= rmc_usec_monotonic_timestamp();
        if (timeout_ts < 0)
            timeout_ts = 0;
    }
            
    nfds = epoll_wait(epollfd, events, RMC_MAX_CONNECTIONS, (timeout_ts == -1)?-1:(timeout_ts / 1000) + 1);

    if (nfds == -1) {
        RMC_LOG_FATAL("epoll_wait(): %s", strerror(errno));
        exit(255);
    }

    // Timeout
    if (nfds == 0) 
        return ETIME;

    // printf("poll_wait(): %d results\n", nfds);
    while(nfds--) {
        int res = 0;
        uint8_t op_res = 0;
        rmc_index_t c_ind = events[nfds].data.u32;

        RMC_LOG_COMMENT("%s:%d - %s%s%s",
               _index(c_ind, buf), _descriptor(ctx, c_ind),
               ((events[nfds].events & EPOLLIN)?" read":""),
               ((events[nfds].events & EPOLLOUT)?" write":""),
               ((events[nfds].events & EPOLLHUP)?" disconnect":""));


        if (events[nfds].events & EPOLLIN) {
            errno = 0;
            res = rmc_sub_read(ctx, c_ind, &op_res);
            // Did we read a loopback message we sent ourselves?
            RMC_LOG_DEBUG("read result: %s - %s", _op_res_string(op_res),   strerror(res));
        }

        if (events[nfds].events & EPOLLOUT) {
            if (rmc_sub_write(ctx, c_ind, &op_res) != 0) {
                rmc_sub_close_connection(ctx, c_ind);
            }
        }
    }

    return 0;
}



void test_rmc_proto_sub(char* mcast_group_addr,
                        char* mcast_if_addr,
                        int mcast_port,
                        rmc_context_id_t node_id,
                        uint8_t* node_id_map,
                        int node_id_map_size)
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
    usec_timestamp_t timeout_ts = 0;
    usec_timestamp_t exit_ts = 0;
    uint8_t *conn_vec_mem = 0;
    int do_exit = 0;

    // Indexed by publisher node_id
    sub_expect_t expect[node_id_map_size];


    epollfd = epoll_create1(0);
    for (ind = 0; ind < node_id_map_size; ++ind) {
        expect[ind].status = RMC_TEST_SUB_INACTIVE;
        expect[ind].max_received = 0;
        expect[ind].max_expected = 0;

        // Check if we are expecting traffic on this one
        if (node_id_map[ind]) 
            expect[ind].status = RMC_TEST_SUB_NOT_STARTED;
    }
    
    if (epollfd == -1) {
        perror("epoll_create1");
        exit(255);
    }

    ctx = malloc(sizeof(rmc_sub_context_t));
    
    conn_vec_mem = malloc(sizeof(rmc_connection_t)*RMC_MAX_CONNECTIONS);
    memset(conn_vec_mem, 0, sizeof(rmc_connection_t)*RMC_MAX_CONNECTIONS);
    rmc_sub_init_context(ctx,
                         0, // Assign random context id
                         mcast_group_addr,
                         mcast_if_addr,
                         mcast_port,
                         (user_data_t) { .i32 = epollfd },
                         poll_add, poll_modify, poll_remove,
                         conn_vec_mem, RMC_MAX_CONNECTIONS,
                         0,0);

    _test("rmc_proto_test_sub[%d.%d] activate_context(): %s",
          1, 1,
          rmc_sub_activate_context(ctx));

    rmc_sub_set_announce_callback(ctx, announce_cb);

    RMC_LOG_INFO("ctx[%.9X] mcast_addr[%s] mcast_port[%d]",
                  rmc_sub_context_id(ctx), mcast_group_addr, mcast_port);

    while(1) {
        sub_packet_t* pack = 0;
        packet_id_t first_pid = 0;
        packet_id_t last_pid = 0;
        usec_timestamp_t current_ts = rmc_usec_monotonic_timestamp();

        rmc_sub_timeout_get_next(ctx, &timeout_ts);
        
        while(timeout_ts != -1 && timeout_ts < current_ts) {
            rmc_sub_timeout_process(ctx);
            rmc_sub_timeout_get_next(ctx, &timeout_ts);
        }

        RMC_LOG_COMMENT("timeout [%ld] msec", (timeout_ts == -1)?-1:(timeout_ts  - current_ts)/1000);
        if (process_events(ctx, epollfd, timeout_ts) == ETIME) {
            RMC_LOG_COMMENT("Got timeout");
            continue;
        }
        else 
            RMC_LOG_DEBUG("No timeout");

        // Process as many packets as possible.
        
        while((pack = rmc_sub_get_next_dispatch_ready(ctx))) {
            if (!first_pid)
                first_pid = pack->pid;

            last_pid = pack->pid;
            if (!process_incoming_packet(ctx, pack, expect, node_id_map_size)) {
                do_exit = 1;
                break;
            }
        }
        RMC_LOG_COMMENT("max_pid_ready[%lu]  max_pid_received[%lu]",
                      ctx->publishers[0].max_pid_ready,  ctx->publishers[0].max_pid_ready);

        if (do_exit)

            break;
    }
    rmc_sub_deactivate_context(ctx);
    
    RMC_LOG_INFO("Done.");
    exit(0);
}
