// Copyright (C) 2018, Jaguar Land Rover This program is licensed
// under the terms and conditions of the Mozilla Public License,
// version 2.0.  The full text of the Mozilla Public License is at
// https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "rmc_sub.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>


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


__attribute__ ((unused))
static uint8_t _test_print_publisher(sub_publisher_t* pub, void* dt)
{
    int indent = (int) (uint64_t) dt;

    printf("%*cPublisher %p\n", indent*2, ' ', pub);
    if (sub_packet_list_size(&pub->received_pid) > 0) {
        printf("%*cReceived packets:\n", indent*3, ' ');
        sub_packet_list_for_each(&pub->received_pid, _test_print_pending, (void*) ((uint64_t)indent + 2));
    } else
        printf("%*cReceived packets: [None]\n", indent*2, ' ');

    putchar('\n');

    return 1;
}


static void test_sequence(char* test, sub_packet_list_t* list, packet_id_t start, packet_id_t stop)
{
    packet_id_t pid = start;
    sub_packet_node_t* node = 0;

    node = sub_packet_list_head(list);
    while(node) {
        if (node->data->pid != pid) {
            printf("sub_test: failed  %s. Wanted pid %lu, got %lu\n",
                   test, pid, node->data->pid);
            exit(255);
        }
        node = sub_packet_list_next(node);

        // Are we descend
        if (start < stop)
            pid++;
        else
            pid--;
    }
}

static void add_received_packets(sub_publisher_t* pub,
                                 usec_timestamp_t ts_current,
                                 ...)
{
    va_list ap;
    packet_id_t start;
    packet_id_t stop;

    va_start(ap, ts_current);

    start = va_arg(ap, packet_id_t);
    stop = va_arg(ap, packet_id_t);
    while(start && stop) {
        packet_id_t pid;
        char buf[16];

        for(pid = start; pid != stop + 1; ++pid) {
            sprintf(buf, "%lu", pid);
            sub_packet_received(pub, pid,
                                buf, strlen(buf)+1,
                                1,
                                ts_current, user_data_nil());
        }

        start = va_arg(ap, packet_id_t);
        stop = va_arg(ap, packet_id_t);

    }
    va_end(ap);
}

static void test_interval_list(char* test,
                               sub_publisher_t* pub,
                               ...)
{
    va_list ap;
    packet_id_t start;
    packet_id_t stop;
    sub_pid_interval_node_t* node = sub_pid_interval_list_head(&pub->received_interval);
    uint32_t argc = 0;

    va_start(ap, pub);

    while(node) {
        start = va_arg(ap, packet_id_t);
        stop = va_arg(ap, packet_id_t);

        // Did we run out of arguments?
        if (!start || !stop) {
            printf("sub_test: failed  %s: Got %d interval tuples. List has %d elements",
                   test, argc, sub_pid_interval_list_size(&pub->received_interval));
            exit(255);
        }

        // Does the interval match?
        if (node->data.first_pid != start ||
            node->data.last_pid != stop) {
            printf("sub_test: failed  %s. Wanted interval 3-5, got %lu-%lu\n",
                   test,
                   node->data.first_pid,
                   node->data.last_pid);
            exit(255);
        }
        argc++;
        node = sub_pid_interval_list_next(node);
    }
    va_end(ap);
    // Do we still have args?
    start = va_arg(ap, packet_id_t);
    stop = va_arg(ap, packet_id_t);

    if (start || stop) {
        printf("sub_test: failed  %s. %d interval tuples in argument. List size is %d\n",
               test,
               argc,
               sub_pid_interval_list_size(&pub->received_interval));
        exit(255);
    }
}



void test_sub(void)
{
    sub_publisher_t pub1;
    sub_publisher_t pub2;
    sub_publisher_t pub3;
    sub_packet_t* pack = 0;
    sub_packet_list_t dispatch_ready;

    sub_packet_list_init(&dispatch_ready, 0, 0, 0);

    sub_init_publisher(&pub1);
    sub_init_publisher(&pub2);
    sub_init_publisher(&pub3);

    //--------
    // Basic processing of packages
    //--------
    add_received_packets(&pub1, 0,
                         1, 5,
                         0, 0);

    // Check sequence
    test_sequence("1.1", &pub1.received_pid, 1, 5);
    sub_process_received_packets(&pub1, &dispatch_ready);

    // Received queue should be empty.
    if (sub_packet_list_size(&pub1.received_pid)) {
        printf("sub_test: failed  1.2. Wanted size 0, got %d\n",
               sub_packet_list_size(&pub1.received_pid));
        exit(255);
    }

    test_sequence("1.3", &dispatch_ready, 1, 5);

    // Dispatch all packets and check that they disappear.
    // Packet 1.
    sub_packet_list_pop_head(&dispatch_ready, &pack);

    test_sequence("1.4", &dispatch_ready, 2, 5);

    // Packet 2.
    sub_packet_list_pop_head(&dispatch_ready, &pack);
    test_sequence("1.5", &dispatch_ready, 3, 5);

    // Packet 3.
    sub_packet_list_pop_head(&dispatch_ready, &pack);
    test_sequence("1.6", &dispatch_ready, 4, 5);

    // Packet 4.
    sub_packet_list_pop_head(&dispatch_ready, &pack);
    test_sequence("1.7", &dispatch_ready, 5, 5);

    // Packet 5.
    sub_packet_list_pop_head(&dispatch_ready, &pack);
    if (sub_packet_list_size(&dispatch_ready)) {
        printf("sub_test: failed  1.8. Wanted size 0, got %d\n",
               sub_packet_list_size(&dispatch_ready));
        exit(255);
    }

    // Packet 1-5 should be in the received list.
    test_interval_list("1.9",
                       &pub1,
                       1, 5,
                       0, 0);


    // Reset pub1 and dispatch_ready.
    sub_reset_publisher(&pub1, 0);
    sub_packet_list_empty(&dispatch_ready);

    //--------
    // Out of order packages.
    //--------

    // Middle stream out of order
    add_received_packets(&pub1, 0,
                         1, 1,
                         3, 3,
                         2, 2,
                         4, 4,
                         0, 0);

    // Check sequence
    test_sequence("2.1", &pub1.received_pid, 1, 4);

    sub_process_received_packets(&pub1, &dispatch_ready);
    test_sequence("2.2", &dispatch_ready, 1, 4);


    // Start out-of-order packages
    sub_reset_publisher(&pub1, 0);
    sub_packet_list_empty(&dispatch_ready);

    add_received_packets(&pub1, 0,
                         2, 2,
                         1, 1,
                         3, 3,
                         4, 4,
                         0, 0);

    // Check sequence
    test_sequence("2.3", &pub1.received_pid, 1, 4);

    sub_process_received_packets(&pub1, &dispatch_ready);
    test_sequence("2.4", &dispatch_ready, 1, 4);

    sub_reset_publisher(&pub1, 0);
    sub_packet_list_empty(&dispatch_ready);

    // End out-of-order packages
    add_received_packets(&pub1, 0,
                         1, 1,
                         2, 2,
                         4, 4,
                         3, 3,
                         0, 0);

    // Check sequence
    test_sequence("2.5", &pub1.received_pid, 1, 4);

    sub_process_received_packets(&pub1, &dispatch_ready);
    test_sequence("2.6", &dispatch_ready, 1, 4);

    sub_reset_publisher(&pub1, 0);
    sub_packet_list_empty(&dispatch_ready);


    //--------
    // Test single missing packages.
    //--------

    add_received_packets(&pub1, 0,
                         1, 2,
                         // 3-3
                         4, 5,
                         0, 0);

    test_interval_list("3.1", &pub1,
                       1,2,
                       4,5,
                       0,0);
/*

    //
    // Test multiple missing packages.
    //
    reset_context(&ctx);

    add_received_packets(&pub1, 0,
                         1, 2,
                         // 3-5
                         6, 7,
                         0, 0);

    while(sub_pid_interval_list_pop_head(&pub1, &intv));

    // Check if we get a "3-5" as a missing packet
    sub_get_missing_packets(&pub1, &pub1);

    test_interval_list("3.2", &pub1,
                       3,5,
                       0,0);


    //--------
    // Test multiple missing packages in multiple holes
    //--------

    reset_context(&ctx);

    add_received_packets(&pub1, 0,
                         1, 2,
                         // 3-5
                         6, 7,
                         // 8-9
                         10, 10,
                         // 11-13
                         14, 15,
                         // 16-19
                         20, 21,
                         0, 0);

    while(sub_pid_interval_list_pop_head(&pub1, &intv));

    // Check if we get a 3-5, 7-9, 11-13, 16-19 as a missing packets

    sub_get_missing_packets(&pub1, &pub1);


    test_interval_list("3.3", &pub1,
                       3,5,
                       8,9,
                       11,13,
                       16,19,
                       0,0);


    //
    //--------
    // Test that we correctly can handle a package stream
    // that starts later than pid 1
    //--------
    //
    reset_context(&ctx);

    add_received_packets(&pub1, 0,
                         100, 101,
                         // 102-102
                         103, 104,
                         0, 0);

    while(sub_pid_interval_list_pop_head(&pub1, &intv));


    sub_get_missing_packets(&pub1, &pub1);


    test_interval_list("4.1", &pub1,
                       102, 102,
                       0,0);

    //
    //--------
    // Test that we correctly can handle holes after we have
    // successfully procesed packages
    //--------
    //
    reset_context(&ctx);

    add_received_packets(&pub1, 0,
                         1, 2,
                         // 3-5 missing
                         6, 7,
                         // 8-9 missing
                         10, 10,
                         // 11-13 missing
                         14, 15,
                         // 16-19 missing
                         20, 21,
                         0, 0);

    // sub_process_received_packets() should
    // move 1 and 2 to ready queue.
    sub_process_received_packets(&pub1);

    test_sequence("5.1", &ctx.dispatch_ready, 1, 2);

    while(sub_pid_interval_list_pop_head(&pub1, &intv));

    // We should still have the same holes
    sub_get_missing_packets(&pub1, &pub1);

    test_interval_list("5.2", &pub1,
                       3,5,
                       8,9,
                       11,13,
                       16,19,
                       0,0);

    // Insert one missing packet. Still leaving a hole at 3 and 5
    add_received_packets(&pub1, 0,
                         4,4,
                         0,0);

    // Will move no packets from received to ready since we still
    // need pid 3 and 5 to get a complete sequence from 1-7
    sub_process_received_packets(&pub1);

    while(sub_pid_interval_list_pop_head(&pub1, &intv));

    // We should still have the same holes
    sub_get_missing_packets(&pub1, &pub1);

    test_interval_list("5.3", &pub1,
                       3,3,
                       5,5,
                       8,9,
                       11,13,
                       16,19,
                       0,0);

    // Insert packet #3, which should be moved immedately over to the ready queue
    add_received_packets(&pub1, 0,
                         3,3,
                         0,0);

    // need pid 5 to get a complete sequence from 1-7
    sub_process_received_packets(&pub1);

    while(sub_pid_interval_list_pop_head(&pub1, &intv));


    // We should still have the same holes
    sub_get_missing_packets(&pub1, &pub1);

    // Ready packets should be 1-3
    test_sequence("5.4", &ctx.dispatch_ready, 1, 3);

    test_interval_list("5.5", &pub1,
                       5,5,
                       8,9,
                       11,13,
                       16,19,
                       0,0);

    // Dispatch the ready packets
    // pid 1
    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);

    // pid 2
    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);
    // pid 3
    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);

    // Ready queue is empty.
    // We are still lacking pid 5 before we can
    // move 1-7 to
    while(sub_pid_interval_list_pop_head(&pub1, &intv));


    // We should still have the same holes
    sub_get_missing_packets(&pub1, &pub1);

    test_interval_list("5.7", &pub1,
                       5,5,
                       8,9,
                       11,13,
                       16,19,
                       0,0);



    // Insert packet 4, which should
    // enable 4-7 to be moved to ready queue
    add_received_packets(&pub1, 0,
                         5,5,
                         0,0);

    sub_process_received_packets(&pub1);

    while(sub_pid_interval_list_pop_head(&pub1, &intv));


    // We should still have the same holes
    sub_get_missing_packets(&pub1, &pub1);

    // Ready packets should be 4-7
    test_sequence("5.8", &ctx.dispatch_ready, 4, 7);

    test_interval_list("5.9", &pub1,
                       8,9,
                       11,13,
                       16,19,
                       0,0);

    // Plug the 11-13 and 15-10 hole
    add_received_packets(&pub1, 0,
                         11,13,
                         16,19,
                         0,0);

    // process packages should not change since we still need pid
    // 8-9
    sub_process_received_packets(&pub1);

    while(sub_pid_interval_list_pop_head(&pub1, &intv));


    // We should still have the same holes
    sub_get_missing_packets(&pub1, &pub1);


    // Ready packets should be 4-7
    test_sequence("5.10", &ctx.dispatch_ready, 4, 7);

    test_interval_list("5.11", &pub1,
                       8,9,
                       0,0);

    // Plug the 8-9 hole, which should
    // enable all pid, 8-21, to be moved
    // to ready
    add_received_packets(&pub1, 0,
                         8,9,
                         0,0);

    // process packages to move all remaining
    // received packages to ready
    sub_process_received_packets(&pub1);

    while(sub_pid_interval_list_pop_head(&pub1, &intv));

    // We should still have the same holes
    sub_get_missing_packets(&pub1, &pub1);

    // Ready packets should be 4-21
    test_sequence("5.12", &ctx.dispatch_ready, 4, 21);

    if (sub_pid_interval_list_size(&pub1)) {
        printf("sub_test: failed  5.12 Wanted size 0, got %d\n",
               sub_pid_interval_list_size(&pub1));
        exit(255);
    }


    //--------
    // Test that we correctly drop dup packets
    //--------

    reset_context(&ctx);

    add_received_packets(&pub1, 0,
                         1, 2,
                         // 3-5
                         6, 7,
                         // 8-9
                         10, 10,
                         // 11-13
                         14, 15,
                         // 16-19
                         20, 21,
                         0, 0);

    // Check that we drop dups in the received queue

    if (!sub_packet_is_duplicate(&pub1, 1)) {
        printf("sub_test: failed  6.1 Failed dup packet detection.\n");
        exit(255);
    }

    // Process packet 1 and 2.
    sub_process_received_packets(&pub1);

    // Check that we drop dups in the ready queue
    if (!sub_packet_is_duplicate(&pub1, 1)) {
        printf("sub_test: failed  6.2 Failed dup packet detection.\n");
        exit(255);
    }

    // Plug the 3-5 hole
    add_received_packets(&pub1, 0,
                         3, 5,
                         0, 0);

    // Process packet 3-5.
    sub_process_received_packets(&pub1);

    // Check that we drop dups in the ready queue
    if (!sub_packet_is_duplicate(&pub1, 1)) {
        printf("sub_test: failed  6.3 Failed dup packet detection.\n");
        exit(255);
    }

    // Check that we drop dups in the ready queue
    if (!sub_packet_is_duplicate(&pub1, 10)) {
        printf("sub_test: failed  6.4 Failed dup packet detection.\n");
        exit(255);
    }

    // Dispatch packet 1-4
    // 1
    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);

    // 2
    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);

    // 3
    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);

    // 4
    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);


    // Check that we cannot dup dispatched packets
    if (!sub_packet_is_duplicate(&pub1, 1)) {
        printf("sub_test: failed  6.5 Failed dup packet detection.\n");
        exit(255);
    }

    if (!sub_packet_is_duplicate(&pub1, 5)) {
        printf("sub_test: failed  6.6 Failed dup packet detection.\n");
        exit(255);
    }

    if (!sub_packet_is_duplicate(&pub1, 10)) {
        printf("sub_test: failed  6.7 Failed dup packet detection.\n");
        exit(255);
    }

    // Failure case detected during higher-level debugging
    // If we start with a pid different than 1, we fail
    reset_context(&ctx);
    add_received_packets(&pub1, 0,
                         2, 2,
                         0,0);

    sub_process_received_packets(&pub1);

    if (sub_packet_list_size(&pub1.received) != 0) {
        printf("sub_test: failed  7.0 Wanted zero.\n");
        exit(255);
    }

    if (sub_packet_list_size(&ctx.dispatch_ready) != 1) {
        printf("sub_test: failed  7.1 Wanted 1.\n");
        exit(255);
    }

    add_received_packets(&pub1, 0,
                         3, 3,
                         0, 0);

    // Failure case detected during higher-level debugging
    sub_process_received_packets(&pub1);

    if (sub_packet_list_size(&pub1.received) != 0) {
        printf("sub_test: failed  7.2 Wanted zero.\n");
        exit(255);
    }

    if (sub_packet_list_size(&ctx.dispatch_ready) != 2) {
        printf("sub_test: failed  7.3 Wanted 2.\n");
        exit(255);
    }

    //
    // Test functionality to harvest packets that are ready to be acknowledged.
    //
    reset_context(&ctx);
    add_received_packets(&pub1, 100,
                         1, 2,
                         0, 0);

    add_received_packets(&pub1, 200,
                         3, 4,
                         0, 0);

    add_received_packets(&pub1, 300,
                         5, 6,
                         0, 0);

    sub_process_received_packets(&pub1);

    // Dispatch all packets, moving them to the ack queue.
    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);

    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);

    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);

    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);

    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);

    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);

    sub_packet_list_init(&lst, 0, 0, 0);

    // Grab all older than 100.
    sub_get_timed_out_packets(&ctx, 100, &lst);

    test_sequence("8.1", &lst, 1, 2);

    // Grab all older than 200.
    sub_packet_list_empty(&lst);
    sub_get_timed_out_packets(&ctx, 200, &lst);
    test_sequence("8.2", &lst, 1, 4);

    // Grab all older than 300.
    sub_packet_list_empty(&lst);
    sub_get_timed_out_packets(&ctx, 300, &lst);
    test_sequence("8.3", &lst, 1, 4);


    // Replicate error found while testing.
    // Replicate recive 1-6. dispatch/ack 1-6. Receive 7.
    //
    reset_context(&ctx);
    add_received_packets(&pub1, 0,
                         1, 6,
                         0, 0);

    sub_process_received_packets(&pub1);

    // Dispatch all  six packets, moving them to the ack queue.
    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);
    sub_packet_acknowledged(pack);

    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);
    sub_packet_acknowledged(pack);

    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);
    sub_packet_acknowledged(pack);

    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);
    sub_packet_acknowledged(pack);

    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);
    sub_packet_acknowledged(pack);

    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);
    sub_packet_acknowledged(pack);


    sub_packet_list_empty(&lst);
    if (sub_get_dispatch_ready_count(&ctx) != 0) {
        printf("sub_test: failed 9.1 Wanted 0, got %d.\n", sub_get_dispatch_ready_count(&ctx));
        exit(255);
    }

    // Add packet 7
    add_received_packets(&pub1, 0,
                         7, 7,
                         0,0);

    sub_process_received_packets(&pub1);

    if (sub_get_dispatch_ready_count(&ctx) != 1) {
        printf("sub_test: failed 9.2 Wanted 1, got %d.\n", sub_get_dispatch_ready_count(&ctx));
        exit(255);
    }

    pack = sub_get_next_dispatch_ready(&ctx);
    if (!pack) {
        printf("sub_test: failed 9.3 No dispatch ready pack found.\n");
        exit(255);
    }
    if (pack->pid != 7) {
        printf("sub_test: failed 9.4 Wanted pid 7. Got %lu.\n", pack->pid);
        exit(255);
    }

    reset_context(&ctx);
*/
}
