// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
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
    printf("%*c  Parent node     %p\n", indent*2, ' ', pack->owner_node);
    printf("%*c  Payload Length  %d\n", indent*2, ' ', pack->payload_len);
    printf("%*c  Received time   %ld\n", indent*2, ' ', pack->received_ts);
    putchar('\n');
    return 1;
}

static uint8_t _test_print_interval(intv_node_t* node, void* dt)
{
    packet_interval_t intv =  node->data;
    int indent = (int) (uint64_t) dt;

    printf("%*cInterval: %lu - %lu\n", indent*2, ' ', intv.first_pid, intv.last_pid);
    return 1;
}

static uint8_t _test_print_interval_list(intv_list_t* list)
{
    puts("Interval:");
    intv_list_for_each(list, _test_print_interval, (void*) 1);
    return 1;
}


static uint8_t _test_print_publisher(sub_publisher_node_t* node, void* dt)
{
    sub_publisher_t* pub = node->data;
    int indent = (int) (uint64_t) dt;

    printf("%*cPublisher %p\n", indent*2, ' ', pub);
    if (sub_packet_list_size(&pub->received) > 0) {
        printf("%*cReceived packets:\n", indent*3, ' ');
        sub_packet_list_for_each(&pub->received, _test_print_pending, (void*) ((uint64_t)indent + 2));
    } else
        printf("%*cReceived packets: [None]\n", indent*2, ' ');

    putchar('\n');
        
    return 1;
}

void test_print_sub_context(sub_context_t* ctx)
{
    printf("Context           %p\n", ctx);
    if (sub_packet_list_size(&ctx->dispatch_ready) > 0) {
        printf("Dispatch-ready packets:\n");
        sub_packet_list_for_each(&ctx->dispatch_ready, _test_print_pending, (void*) ((uint64_t) 1));
    } else
        printf("Dispatch-ready packets: [None]\n");

    if (sub_packet_list_size(&ctx->ack_ready) > 0) {
        printf("Acknowledge-ready packets:\n");
        sub_packet_list_for_each(&ctx->ack_ready, _test_print_pending, (void*) ((uint64_t) 1));
    } else
        printf("Ackonwledge-ready packets: [None]\n");


    if (sub_publisher_list_size(&ctx->publishers) > 0) {
        printf("\nPublishers:\n");
        sub_publisher_list_for_each(&ctx->publishers, _test_print_publisher, (void*) (uint64_t) 1);
    } else
        printf("Publishers: [None]\n");

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
            sub_packet_received(pub, pid, buf, strlen(buf)+1, ts_current, user_data_nil());
        }

        start = va_arg(ap, packet_id_t);
        stop = va_arg(ap, packet_id_t);

    }
    va_end(ap);
}

static void test_interval_list(char* test,
                               intv_list_t* list,
                               ...)
{
    va_list ap;
    packet_id_t start;
    packet_id_t stop;
    intv_node_t* node = intv_list_head(list);
    uint32_t argc;

    va_start(ap, list);

    while(node) {
        start = va_arg(ap, packet_id_t);
        stop = va_arg(ap, packet_id_t);

        // Did we run out of arguments?
        if (!start || !stop) {
            printf("sub_test: failed  %s: Got %d interval tuples. List has %d elements",
                   test, argc, intv_list_size(list));
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
        node = intv_list_next(node);
    }
    va_end(ap);
    // Do we still have args?
    start = va_arg(ap, packet_id_t);
    stop = va_arg(ap, packet_id_t);
    
    if (start || stop) {
        printf("sub_test: failed  %s. %d interval tuples in argument. List size is %d\n",
               test,
               argc,
               intv_list_size(list));
        exit(255);
    }
}



void reset_context(sub_context_t* ctx)
{
    sub_packet_t* pack = 0;
    sub_publisher_t* pub;
    sub_publisher_node_t* p_node;
    sub_publisher_list_t lst;
    
    sub_publisher_list_init(&lst, 0,0, 0);
    p_node = sub_publisher_list_head(&ctx->publishers);
    while(p_node) {
        pub = p_node->data;
        sub_reset_publisher(pub, 0);
        sub_publisher_list_push_head(&lst, pub);
        p_node = sub_publisher_list_head(&ctx->publishers);
    }

    while((pack = sub_get_next_dispatch_ready(ctx))) 
        sub_packet_dispatched(pack);

    while((pack = sub_get_next_acknowledge_ready(ctx))) 
        sub_packet_acknowledged(pack);

    while(sub_publisher_list_head(&lst))  {
        sub_publisher_list_pop_head(&lst, &pub);
        sub_init_publisher(pub, ctx);
    }
        
        

    return;
}


void test_sub(void)
{
    sub_context_t ctx;
    sub_publisher_t pub1;
    sub_publisher_t pub2;
    sub_publisher_t pub3;
    sub_packet_t* pack = 0;
    packet_id_t pid = 0;
    intv_list_t holes;
    sub_packet_node_t* node = 0;
    packet_interval_t intv = { .first_pid =0, .last_pid = 0};
    sub_packet_list_t lst;

    sub_init_context(&ctx);
    intv_list_init(&holes, 0, 0, 0);

    
    sub_init_publisher(&pub1, &ctx);
    sub_init_publisher(&pub2, &ctx);
    sub_init_publisher(&pub3, &ctx);



    //--------
    // Basic processing of packages
    //--------

    add_received_packets(&pub1, 0,
                         1, 5,
                         0, 0);

    // Check sequence
    test_sequence("1.1", &pub1.received, 1, 5);
    sub_process_received_packets(&pub1);

    // Received queue should be empty.
    if (sub_packet_list_size(&pub1.received)) {
        printf("sub_test: failed  1.2. Wanted size 0, got %d\n",
               sub_packet_list_size(&pub1.received));
        exit(255);
    }
        
    test_sequence("1.3", &ctx.dispatch_ready, 1, 5);

    // Dispatch all packets and check that they disappear.
    // Packet 1.
    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);
    test_sequence("1.4", &ctx.dispatch_ready, 2, 5);

    // Packet 2.
    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);
    test_sequence("1.5", &ctx.dispatch_ready, 3, 5);

    // Packet 3.
    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);
    test_sequence("1.6", &ctx.dispatch_ready, 4, 5);

    // Packet 4.
    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);
    test_sequence("1.7", &ctx.dispatch_ready, 5, 5);

    // Packet 5.
    pack = sub_get_next_dispatch_ready(&ctx);
    sub_packet_dispatched(pack);
    if (sub_packet_list_size(&ctx.dispatch_ready)) {
        printf("sub_test: failed  1.8. Wanted size 0, got %d\n",
               sub_packet_list_size(&ctx.dispatch_ready));
        exit(255);
    }

    //
    // Packet 1-5 should now be in the ack_ready list
    //
    test_sequence("1.9", &ctx.ack_ready, 1, 5);

    // Validate packet 1
    pack = sub_get_next_acknowledge_ready(&ctx);
    if (pack->pid != 1) {
        printf("sub_test: failed  1.10. Wanted pid 1, got %lu\n",
               pack->pid);
        exit(255);
    }
    sub_packet_acknowledged(pack);
    test_sequence("1.11", &ctx.ack_ready, 2, 5);

    // Validate packet 2
    pack = sub_get_next_acknowledge_ready(&ctx);;
    if (pack->pid != 2) {
        printf("sub_test: failed  1.12. Wanted pid 2, got %lu\n",
               pack->pid);
        exit(255);
    }
    sub_packet_acknowledged(pack);
    test_sequence("1.12", &ctx.ack_ready, 3, 5);
    
    // Validate packet 3
    pack = sub_get_next_acknowledge_ready(&ctx);;
    if (pack->pid != 3) {
        printf("sub_test: failed  1.13. Wanted pid 3, got %lu\n",
               pack->pid);
        exit(255);
    }
    sub_packet_acknowledged(pack);
    test_sequence("1.14", &ctx.ack_ready, 4, 5);

    // Validate packet 4
    pack = sub_get_next_acknowledge_ready(&ctx);;
    if (pack->pid != 4) {
        printf("sub_test: failed  1.14. Wanted pid 4, got %lu\n",
               pack->pid);
        exit(255);
    }
    sub_packet_acknowledged(pack);
    test_sequence("1.15", &ctx.ack_ready, 5, 5);

    // Validate packet 5
    pack = sub_get_next_acknowledge_ready(&ctx);;
    if (pack->pid != 5) {
        printf("sub_test: failed  1.16. Wanted pid 5, got %lu\n",
               pack->pid);
        exit(255);
    }
    sub_packet_acknowledged(pack);


    // Ack ready should be empty
    if (sub_packet_list_size(&ctx.ack_ready)) {
        printf("sub_test: failed  1.17. Wanted size 0, got %d\n",
               sub_packet_list_size(&ctx.ack_ready));
        exit(255);
    }
    
    // Reset pub1
    reset_context(&ctx);
    
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
    test_sequence("2.1", &pub1.received, 1, 4);

    sub_process_received_packets(&pub1);
    test_sequence("2.2", &ctx.dispatch_ready, 1, 4);
    

    // Start out-of-order packages
    reset_context(&ctx);
    add_received_packets(&pub1, 0,
                         2, 2,
                         1, 1,
                         3, 3,
                         4, 4,
                         0, 0);

    // Check sequence
    test_sequence("2.3", &pub1.received, 1, 4);

    sub_process_received_packets(&pub1);
    test_sequence("2.4", &ctx.dispatch_ready, 1, 4);
    
    reset_context(&ctx);

    // End out-of-order packages
    add_received_packets(&pub1, 0,
                         1, 1,
                         2, 2,
                         4, 4,
                         3, 3,
                         0, 0);

    // Check sequence
    test_sequence("2.5", &pub1.received, 1, 4);

    sub_process_received_packets(&pub1);
    test_sequence("2.6", &ctx.dispatch_ready, 1, 4);

    reset_context(&ctx);


    //--------
    // Test single missing packages.
    //--------

    add_received_packets(&pub1, 0,
                         1, 2,
                         // 3-3
                         4, 5,
                         0, 0);

    // Check if we get a "3" as a missing packet
    sub_get_missing_packets(&pub1, &holes);

    test_interval_list("3.1", &holes,
                       3,3,
                       0,0);

    //
    // Test multiple missing packages.
    // 
    reset_context(&ctx);

    add_received_packets(&pub1, 0,
                         1, 2,
                         // 3-5
                         6, 7,
                         0, 0);

    while(intv_list_pop_head(&holes, &intv));

    // Check if we get a "3-5" as a missing packet
    sub_get_missing_packets(&pub1, &holes);

    test_interval_list("3.2", &holes,
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

    while(intv_list_pop_head(&holes, &intv));

    // Check if we get a 3-5, 7-9, 11-13, 16-19 as a missing packets

    sub_get_missing_packets(&pub1, &holes);


    test_interval_list("3.3", &holes,
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

    while(intv_list_pop_head(&holes, &intv));


    sub_get_missing_packets(&pub1, &holes);

    
    test_interval_list("4.1", &holes,
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
                         // 3-5
                         6, 7,
                         // 8-9
                         10, 10,
                         // 11-13
                         14, 15,
                         // 16-19
                         20, 21,
                         0, 0);

    // sub_process_received_packets() should
    // move 1 and 2 to ready queue.
    sub_process_received_packets(&pub1);
    
    test_sequence("5.1", &ctx.dispatch_ready, 1, 2);

    while(intv_list_pop_head(&holes, &intv));

    // We should still have the same holes
    sub_get_missing_packets(&pub1, &holes);

    test_interval_list("5.2", &holes,
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

    while(intv_list_pop_head(&holes, &intv));

    // We should still have the same holes
    sub_get_missing_packets(&pub1, &holes);

    test_interval_list("5.3", &holes,
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

    while(intv_list_pop_head(&holes, &intv));


    // We should still have the same holes
    sub_get_missing_packets(&pub1, &holes);

    // Ready packets should be 1-3
    test_sequence("5.4", &ctx.dispatch_ready, 1, 3);

    test_interval_list("5.5", &holes,
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
    while(intv_list_pop_head(&holes, &intv));


    // We should still have the same holes
    sub_get_missing_packets(&pub1, &holes);

    test_interval_list("5.7", &holes,
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

    while(intv_list_pop_head(&holes, &intv));


    // We should still have the same holes
    sub_get_missing_packets(&pub1, &holes);

    // Ready packets should be 4-7
    test_sequence("5.8", &ctx.dispatch_ready, 4, 7);

    test_interval_list("5.9", &holes,
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

    while(intv_list_pop_head(&holes, &intv));


    // We should still have the same holes
    sub_get_missing_packets(&pub1, &holes);


    // Ready packets should be 4-7
    test_sequence("5.10", &ctx.dispatch_ready, 4, 7);

    test_interval_list("5.11", &holes,
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

    while(intv_list_pop_head(&holes, &intv));

    // We should still have the same holes
    sub_get_missing_packets(&pub1, &holes);

    // Ready packets should be 4-21
    test_sequence("5.12", &ctx.dispatch_ready, 4, 21);

    if (intv_list_size(&holes)) {
        printf("sub_test: failed  5.12 Wanted size 0, got %d\n",
               intv_list_size(&holes));
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
}


