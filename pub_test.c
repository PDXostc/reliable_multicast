// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "rmc_pub.h"
#include <stdio.h>
#include <stdlib.h>

static void _test_pub_free(void* payload, payload_len_t plen)
{
    // We are not allocating payload from heap.
    return;
}

static uint8_t _test_print_pending(pend_node_t* node, void* dt)
{
    pub_pending_packet_t* pack = (pub_pending_packet_t*) node->data;
    int indent = (int) (uint64_t) dt;

    printf("%*cPending Packet  %p\n", indent*2, ' ', pack);
    printf("%*c  PID             %lu\n", indent*2, ' ', pack->pid);
    printf("%*c  Reference count %d\n", indent*2, ' ', pack->ref_count);
    printf("%*c  Parent node     %p\n", indent*2, ' ', pack->parent_node);
    printf("%*c  Payload Length  %d\n", indent*2, ' ', pack->payload_len);
    putchar('\n');
    return 1;
}


static uint8_t _test_print_subscriber(subs_node_t* node, void* dt)
{
    pub_subscriber_t* sub = node->data;
    int indent = (int) (uint64_t) dt;

    printf("%*cSubscriber %p\n", indent*2, ' ', sub);
    if (pend_list_size(&sub->inflight) > 0) {
        printf("%*cInflight packets:\n", indent*3, ' ');
        pend_list_for_each(&sub->inflight, _test_print_pending, (void*) ((uint64_t)indent + 2));
    } else
        printf("%*cInflight packets: [None]\n", indent*2, ' ');

    putchar('\n');
        
    return 1;
}

void test_print_context(pub_context_t* ctx)
{
    printf("Context           %p\n", ctx);
    printf("Next PID          %lu\n", ctx->next_pid);
    if (pend_list_size(&ctx->queued) > 0) {
        printf("Queued Packets:\n");
        pend_list_for_each(&ctx->queued, _test_print_pending, (void*) (uint64_t) 1);
    } else
        printf("Queued Packets: [None]\n");

    if (pend_list_size(&ctx->inflight) > 0) {
        printf("\nInflight Packets:\n");
        pend_list_for_each(&ctx->inflight, _test_print_pending, (void*) (uint64_t) 1);
    } else
        printf("Queued Packets: [None]\n");

    if (subs_list_size(&ctx->subscribers) > 0) {
        printf("\nSubscribers:\n");
        subs_list_for_each(&ctx->subscribers, _test_print_subscriber, (void*) (uint64_t) 1);
    } else
        printf("Queued Packets: [None]\n");

}

void test_pub(void)
{
    pub_context_t ctx;
    pub_subscriber_t sub1;
    pub_subscriber_t sub2;
    pub_subscriber_t sub3;

    pub_pending_packet_t* pack;
    packet_id_t pid = 0;
    

    pub_init_context(&ctx, _test_pub_free);
    pub_init_subscriber(&sub1, &ctx);
    pub_init_subscriber(&sub2, &ctx);
    pub_init_subscriber(&sub3, &ctx);

    pub_queue_packet(&ctx, "1", 2);
    pub_queue_packet(&ctx, "2", 2);
    pub_queue_packet(&ctx, "3", 2);
    pub_queue_packet(&ctx, "4", 2);
    pub_queue_packet(&ctx, "5", 2);
    pub_queue_packet(&ctx, "6", 2);

    pid = pub_queue_packet(&ctx, "7", 2);

    if (pid != 7) {
        printf("Failed pub test 1.1. Wanted packet id 7, got %lu\n",
               pid);
        exit(0);
    }

    
    if (pend_list_size(&ctx.queued) != 7) {
        printf("Failed pub test 1.2. Wanted size 7, got %d\n",
               pend_list_size(&ctx.queued));
        exit(0);
    }

    if (pend_list_size(&ctx.inflight) != 0) {
        printf("Failed pub test 1.3. Wanted size 0, got %d\n",
               pend_list_size(&ctx.inflight));
        exit(0);
    }

    pack = pub_next_queued_packet(&ctx);

    if (pack->pid != 1) {
        printf("Failed pub test 2.1. Wanted packet id 1, got %lu\n",
               pack->pid);
        exit(0);
    }
    pub_packet_sent(&ctx, pack, rmc_usec_monotonic_timestamp());

    pack = pub_next_queued_packet(&ctx);
    if (pack->pid != 2) {
        printf("Failed pub test 2.2. Wanted packet id 2, got %lu\n",
               pack->pid);
        exit(0);
    }
    pub_packet_sent(&ctx, pack, rmc_usec_monotonic_timestamp());

    pack = pub_next_queued_packet(&ctx);
    if (pack->pid != 3) {
        printf("Failed pub test 2.3. Wanted packet id 3, got %lu\n",
               pack->pid);
        exit(0);
    }
    pub_packet_sent(&ctx, pack, rmc_usec_monotonic_timestamp());


    // Check that we have four of original seven packets left in queue.
    if (pend_list_size(&ctx.queued) != 4) {
        printf("Failed pub test 3.1. Wanted size , got %d\n",
               pend_list_size(&ctx.queued));
        exit(0);
    }

    // Check that we have three inflight packets
    if (pend_list_size(&ctx.inflight) != 3) {
        printf("Failed pub test 3.2. Wanted size 3, got %d\n",
               pend_list_size(&ctx.inflight));
        exit(0);
    }

    //
    // Check that all subscribers have three inflight packets.
    //
    if (pend_list_size(&sub1.inflight) != 3) {
        printf("Failed pub test 4.1. Wanted size 3, got %d\n",
               pend_list_size(&sub1.inflight));
        exit(0);
    }

    if (pend_list_size(&sub2.inflight) != 3) {
        printf("Failed pub test 4.2. Wanted size 3, got %d\n",
               pend_list_size(&sub3.inflight));
        exit(0);
    }

    if (pend_list_size(&sub3.inflight) != 3) {
        printf("Failed pub test 4.3. Wanted size 3, got %d\n",
               pend_list_size(&sub3.inflight));
        exit(0);
    }


    // Check that sub is in descending order.
    pack = (pub_pending_packet_t*) pend_list_head(&sub1.inflight)->data;

    if (pack->pid != 3) {
        printf("Failed pub test 5.1. Wanted pid 3, got %lu\n",
               pack->pid);
        exit(0);
    }

    pack = (pub_pending_packet_t*) pend_list_tail(&sub1.inflight)->data;

    if (pack->pid != 1) {
        printf("Failed pub test 5.2. Wanted pid 1, got %lu\n",
               pack->pid);
        exit(0);
    }

    // Ack the first packet.
    pub_packet_ack(&sub1, 1);

    //
    // Do we have two elements left in flight for subscriber.
    //
    if (pend_list_size(&sub1.inflight) != 2) {
        printf("Failed pub test 6.1. Wanted size 2, got %d\n",
               pend_list_size(&sub1.inflight));
        exit(0);
    }

    // Inspect he two elements left and ensure that they are correct.
    pack = (pub_pending_packet_t*) pend_list_head(&sub1.inflight)->data;
    if (pack->pid != 3) {
        printf("Failed pub test 6.2. Wanted pid 2, got %lu\n",
               pack->pid);
        exit(0);
    }

    pack = (pub_pending_packet_t*) pend_list_tail(&sub1.inflight)->data;
    if (pack->pid != 2) {
        printf("Failed pub test 6.3. Wanted size 3, got %lu\n",
               pack->pid);
        exit(0);
    }

    // Inspect the element in the context's inflight queue
    // It should be tail in the queue since we sort on descending.
    pack = (pub_pending_packet_t*) pend_list_tail(&ctx.inflight)->data;
    if (pack->pid != 1) {
        printf("Failed pub test 6.4. Wanted pid 1, got %lu\n",
               pack->pid);
        exit(0);
    }

    // Is ref count correctly decreased?
    if (pack->ref_count != 2) {
        printf("Failed pub test 6.5. Wanted ref count 2, got %d\n",
               pack->ref_count);
        exit(0);
    }

    // Ack the remaining two subscribers for pid 1.
    pub_packet_ack(&sub2, 1);
    pub_packet_ack(&sub3, 1);

    // Check size of inflight elements, which should have been decreased by one.
    if (pend_list_size(&ctx.inflight) != 2) {
        printf("Failed pub test 7.1. Wanted size 2, got %d\n",
               pend_list_size(&ctx.inflight));
        exit(0);
    }        

    // Check that the first inflight package is pid 2
    pack = (pub_pending_packet_t*) pend_list_tail(&ctx.inflight)->data;
    if (pack->pid != 2) {
        printf("Failed pub test 7.2. Wanted pid 2, got %lu\n",
               pack->pid);
        exit(0);
    }

    // Ack the next packet out of order, with pid 3 being acked before pid 2.
    pub_packet_ack(&sub1, 3);
    pub_packet_ack(&sub2, 3);
    pub_packet_ack(&sub3, 3);

    // Check size of inflight elements for sub2, which should be 1 (pid 3)
    if (pend_list_size(&sub2.inflight) != 1) {
        printf("Failed pub test 8.1. Wanted size 1, got %d\n",
               pend_list_size(&sub2.inflight));
        exit(0);
    }        

    // Inspect sub2 to see that its only remaining inflight packet is pid 2
    pack = (pub_pending_packet_t*) pend_list_head(&sub2.inflight)->data;
    if (pack->pid != 2) {
        printf("Failed pub test 8.2. Wanted size 2, got %lu\n",
               pack->pid);
        exit(0);
    }

    // Inspect context's inflight packets and ensure that only pid 3 is left.

    // Check size of inflight elements for ctx, which should be 1 (pid 3)
    if (pend_list_size(&ctx.inflight) != 1) {
        printf("Failed pub test 8.3. Wanted size 1, got %d\n",
               pend_list_size(&ctx.inflight));
        exit(0);
    }        

    // Inspect ctx inflighjt to see that its only remaining inflight
    // packet is pid 2
    pack = (pub_pending_packet_t*) pend_list_head(&ctx.inflight)->data;
    if (pack->pid != 2) {
        printf("Failed pub test 8.3. Wanted size 2, got %lu\n",
               pack->pid);
        exit(0);
    }

    // 
    // Ack packet 2, which is the last one
    //
    pub_packet_ack(&sub1, 2);
    pub_packet_ack(&sub2, 2);
    pub_packet_ack(&sub3, 2);

    // Check size of inflight elements for sub2, which should be 1 (pid 3)
    if (pend_list_size(&sub3.inflight) != 0) {
        printf("Failed pub test 9.1. Wanted size 0, got %d\n",
               pend_list_size(&sub3.inflight));
        exit(0);
    }        

    // Inspect context's inflight packets and ensure that only pid 3 is left.

    // Check size of inflight elements for ctx, which should be 1 (pid 3)
    if (pend_list_size(&ctx.inflight) != 0) {
        printf("Failed pub test 9.2. Wanted size 0, got %d\n",
               pend_list_size(&ctx.inflight));
        exit(0);
    }        

    // Send the rest of the packags.
    pack = pub_next_queued_packet(&ctx);
    if (pack->pid != 4) {
        printf("Failed pub test 10.1. Wanted packet id 4, got %lu\n",
               pack->pid);
        exit(0);
    }
    pub_packet_sent(&ctx, pack, rmc_usec_monotonic_timestamp());

    pack = pub_next_queued_packet(&ctx);
    if (pack->pid != 5) {
        printf("Failed pub test 10.2. Wanted packet id 5, got %lu\n",
               pack->pid);
        exit(0);
    }
    pub_packet_sent(&ctx, pack, rmc_usec_monotonic_timestamp());
    
    pack = pub_next_queued_packet(&ctx);
    if (pack->pid != 6) {
        printf("Failed pub test 10.3. Wanted packet id 6, got %lu\n",
               pack->pid);
        exit(0);
    }
    pub_packet_sent(&ctx, pack, rmc_usec_monotonic_timestamp());
    
    pack = pub_next_queued_packet(&ctx);
    if (pack->pid != 7) {
        printf("Failed pub test 10.4. Wanted packet id 7, got %lu\n",
               pack->pid);
        exit(0);
    }
    pub_packet_sent(&ctx, pack, rmc_usec_monotonic_timestamp());

    // Ack all the packages in a semi-random order
    pub_packet_ack(&sub1, 5);
    pub_packet_ack(&sub2, 5);
    pub_packet_ack(&sub3, 5);

    pub_packet_ack(&sub1, 7);
    pub_packet_ack(&sub2, 7);
    pub_packet_ack(&sub3, 7);

    pub_packet_ack(&sub1, 6);
    pub_packet_ack(&sub2, 6);
    pub_packet_ack(&sub3, 6);

    pub_packet_ack(&sub1, 4);
    pub_packet_ack(&sub2, 4);
    pub_packet_ack(&sub3, 4);

    // Check that everything is empty
    if (pend_list_size(&ctx.inflight) != 0) {
        printf("Failed pub test 11.1. Wanted size 0, got %d\n",
               pend_list_size(&ctx.inflight));
        exit(0);
    }        
    
    if (pend_list_size(&ctx.queued) != 0) {
        printf("Failed pub test 11.2. Wanted size 0, got %d\n",
               pend_list_size(&ctx.queued));
        exit(0);
    }        
    
    
    if (pend_list_size(&sub1.inflight) != 0) {
        printf("Failed pub test 11.3. Wanted size 0, got %d\n",
               pend_list_size(&sub1.inflight));
        exit(0);
    }        
    
    if (pend_list_size(&sub2.inflight) != 0) {
        printf("Failed pub test 11.4. Wanted size 0, got %d\n",
               pend_list_size(&sub2.inflight));
        exit(0);
    }        
    
    if (pend_list_size(&sub3.inflight) != 0) {
        printf("Failed pub test 11.5. Wanted size 0, got %d\n",
               pend_list_size(&sub3.inflight));
        exit(0);
    }        
    
}

