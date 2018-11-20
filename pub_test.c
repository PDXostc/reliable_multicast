// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "rmc_pub.h"
#include <stdio.h>
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
    putchar('\n');
    return 1;
}


static uint8_t _test_print_subscriber(pub_sub_node_t* node, void* dt)
{
    pub_subscriber_t* sub = node->data;
    int indent = (int) (uint64_t) dt;

    printf("%*cSubscriber %p\n", indent*2, ' ', sub);
    if (pub_packet_list_size(&sub->inflight) > 0) {
        printf("%*cInflight packets:\n", indent*3, ' ');
        pub_packet_list_for_each(&sub->inflight, _test_print_pending, (void*) ((uint64_t)indent + 2));
    } else
        printf("%*cInflight packets: [None]\n", indent*2, ' ');

    putchar('\n');
        
    return 1;
}

void test_print_pub_context(pub_context_t* ctx)
{
    printf("Context           %p\n", ctx);
    printf("Next PID          %lu\n", ctx->next_pid);
    if (pub_packet_list_size(&ctx->queued) > 0) {
        printf("Queued Packets:\n");
        pub_packet_list_for_each(&ctx->queued, _test_print_pending, (void*) (uint64_t) 1);
    } else
        printf("Queued Packets: [None]\n");

    if (pub_packet_list_size(&ctx->inflight) > 0) {
        printf("\nInflight Packets:\n");
        pub_packet_list_for_each(&ctx->inflight, _test_print_pending, (void*) (uint64_t) 1);
    } else
        printf("Queued Packets: [None]\n");

    if (pub_sub_list_size(&ctx->subscribers) > 0) {
        printf("\nSubscribers:\n");
        pub_sub_list_for_each(&ctx->subscribers, _test_print_subscriber, (void*) (uint64_t) 1);
    } else
        printf("Subscribers: [None]\n");

}

void test_pub(void)
{
    pub_context_t ctx;
    pub_subscriber_t sub1;
    pub_subscriber_t sub2;
    pub_subscriber_t sub3;
    pub_subscriber_t* sptr1 = 0;
    pub_subscriber_t* sptr2 = 0;
    pub_subscriber_t* sptr3 = 0;
    pub_packet_t* pack;
    packet_id_t pid = 0;
    pub_sub_list_t sub_lst;
    pub_packet_node_t* pnode = 0;
    usec_timestamp_t ts = 0;

    pub_init_context(&ctx);
    pub_init_subscriber(&sub1, &ctx, user_data_nil());
    pub_init_subscriber(&sub2, &ctx, user_data_nil());
    pub_init_subscriber(&sub3, &ctx, user_data_nil());

    pub_queue_packet(&ctx, "1", 2, user_data_nil());
    pub_queue_packet(&ctx, "2", 2, user_data_nil());
    pub_queue_packet(&ctx, "3", 2, user_data_nil());
    pub_queue_packet(&ctx, "4", 2, user_data_nil());
    pub_queue_packet(&ctx, "5", 2, user_data_nil());
    pub_queue_packet(&ctx, "6", 2, user_data_nil());

    pid = pub_queue_packet(&ctx, "7", 2, user_data_nil());

    if (pid != 7) {
        printf("Failed pub test 1.1. Wanted packet id 7, got %lu\n",
               pid);
        exit(255);
    }
    
    if (pub_packet_list_size(&ctx.queued) != 7) {
        printf("Failed pub test 1.2. Wanted size 7, got %d\n",
               pub_packet_list_size(&ctx.queued));
        exit(255);
    }

    if (pub_packet_list_size(&ctx.inflight) != 0) {
        printf("Failed pub test 1.3. Wanted size 0, got %d\n",
               pub_packet_list_size(&ctx.inflight));
        exit(255);
    }

    pack = pub_next_queued_packet(&ctx);

    if (pack->pid != 1) {
        printf("Failed pub test 2.1. Wanted packet id 1, got %lu\n",
               pack->pid);
        exit(255);
    }
    pub_packet_sent(&ctx, pack, rmc_usec_monotonic_timestamp());

    pack = pub_next_queued_packet(&ctx);
    if (pack->pid != 2) {
        printf("Failed pub test 2.2. Wanted packet id 2, got %lu\n",
               pack->pid);
        exit(255);
    }
    pub_packet_sent(&ctx, pack, rmc_usec_monotonic_timestamp());

    pack = pub_next_queued_packet(&ctx);
    if (pack->pid != 3) {
        printf("Failed pub test 2.3. Wanted packet id 3, got %lu\n",
               pack->pid);
        exit(255);
    }
    pub_packet_sent(&ctx, pack, rmc_usec_monotonic_timestamp());


    // Check that we have four of original seven packets left in queue.
    if (pub_packet_list_size(&ctx.queued) != 4) {
        printf("Failed pub test 3.1. Wanted size 4, got %d\n",
               pub_packet_list_size(&ctx.queued));
        exit(255);
    }

    // Check that we have three inflight packets
    if (pub_packet_list_size(&ctx.inflight) != 3) {
        printf("Failed pub test 3.2. Wanted size 3, got %d\n",
               pub_packet_list_size(&ctx.inflight));
        exit(255);
    }

    //
    // Check that all subscribers have three inflight packets.
    //
    if (pub_packet_list_size(&sub1.inflight) != 3) {
        printf("Failed pub test 4.1. Wanted size 3, got %d\n",
               pub_packet_list_size(&sub1.inflight));
        exit(255);
    }

    if (pub_packet_list_size(&sub2.inflight) != 3) {
        printf("Failed pub test 4.2. Wanted size 3, got %d\n",
               pub_packet_list_size(&sub3.inflight));
        exit(255);
    }

    if (pub_packet_list_size(&sub3.inflight) != 3) {
        printf("Failed pub test 4.3. Wanted size 3, got %d\n",
               pub_packet_list_size(&sub3.inflight));
        exit(255);
    }


    // Check that sub is in descending order.
    pack = (pub_packet_t*) pub_packet_list_head(&sub1.inflight)->data;

    if (pack->pid != 3) {
        printf("Failed pub test 5.1. Wanted pid 3, got %lu\n",
               pack->pid);
        exit(255);
    }

    pack = (pub_packet_t*) pub_packet_list_tail(&sub1.inflight)->data;

    if (pack->pid != 1) {
        printf("Failed pub test 5.2. Wanted pid 1, got %lu\n",
               pack->pid);
        exit(255);
    }

    // Ack the first packet.
    pub_packet_ack(&sub1, 1, 0);

    //
    // Do we have two elements left in flight for subscriber.
    //
    if (pub_packet_list_size(&sub1.inflight) != 2) {
        printf("Failed pub test 6.1. Wanted size 2, got %d\n",
               pub_packet_list_size(&sub1.inflight));
        exit(255);
    }

    // Inspect he two elements left and ensure that they are correct.
    pack = (pub_packet_t*) pub_packet_list_head(&sub1.inflight)->data;
    if (pack->pid != 3) {
        printf("Failed pub test 6.2. Wanted pid 2, got %lu\n",
               pack->pid);
        exit(255);
    }

    pack = (pub_packet_t*) pub_packet_list_tail(&sub1.inflight)->data;
    if (pack->pid != 2) {
        printf("Failed pub test 6.3. Wanted size 3, got %lu\n",
               pack->pid);
        exit(255);
    }

    // Inspect the element in the context's inflight queue
    // It should be tail in the queue since we sort on descending.
    pack = (pub_packet_t*) pub_packet_list_tail(&ctx.inflight)->data;
    if (pack->pid != 1) {
        printf("Failed pub test 6.4. Wanted pid 1, got %lu\n",
               pack->pid);
        exit(255);
    }

    // Is ref count correctly decreased?
    if (pack->ref_count != 2) {
        printf("Failed pub test 6.5. Wanted ref count 2, got %d\n",
               pack->ref_count);
        exit(255);
    }

    // Ack the remaining two subscribers for pid 1.
    pub_packet_ack(&sub2, 1, 0);
    pub_packet_ack(&sub3, 1, 0);

    // Check size of inflight elements, which should have been decreased by one.
    if (pub_packet_list_size(&ctx.inflight) != 2) {
        printf("Failed pub test 7.1. Wanted size 2, got %d\n",
               pub_packet_list_size(&ctx.inflight));
        exit(255);
    }        

    // Check that the first in
    pack = (pub_packet_t*) pub_packet_list_tail(&ctx.inflight)->data;
    if (pack->pid != 2) {
        printf("Failed pub test 7.2. Wanted pid 2, got %lu\n",
               pack->pid);
        exit(255);
    }

    // Ack the next packet out of order, with pid 3 being acked before pid 2.
    pub_packet_ack(&sub1, 3, 0);
    pub_packet_ack(&sub2, 3, 0);
    pub_packet_ack(&sub3, 3, 0);

    // Check size of inflight elements for sub2, which should be 1 (pid 3)
    if (pub_packet_list_size(&sub2.inflight) != 1) {
        printf("Failed pub test 8.1. Wanted size 1, got %d\n",
               pub_packet_list_size(&sub2.inflight));
        exit(255);
    }        

    // Inspect sub2 to see that its only remaining inflight packet is pid 2
    pack = (pub_packet_t*) pub_packet_list_head(&sub2.inflight)->data;
    if (pack->pid != 2) {
        printf("Failed pub test 8.2. Wanted size 2, got %lu\n",
               pack->pid);
        exit(255);
    }

    // Inspect context's inflight packets and ensure that only pid 3 is left.

    // Check size of inflight elements for ctx, which should be 1 (pid 3)
    if (pub_packet_list_size(&ctx.inflight) != 1) {
        printf("Failed pub test 8.3. Wanted size 1, got %d\n",
               pub_packet_list_size(&ctx.inflight));
        exit(255);
    }        

    // Inspect ctx inflighjt to see that its only remaining inflight
    // packet is pid 2
    pack = (pub_packet_t*) pub_packet_list_head(&ctx.inflight)->data;
    if (pack->pid != 2) {
        printf("Failed pub test 8.3. Wanted size 2, got %lu\n",
               pack->pid);
        exit(255);
    }

    // 
    // Ack packet 2, which is the last one
    //
    pub_packet_ack(&sub1, 2, 0);
    pub_packet_ack(&sub2, 2, 0);
    pub_packet_ack(&sub3, 2, 0);

    // Check size of inflight elements for sub2, which should be 1 (pid 3)
    if (pub_packet_list_size(&sub3.inflight) != 0) {
        printf("Failed pub test 9.1. Wanted size 0, got %d\n",
               pub_packet_list_size(&sub3.inflight));
        exit(255);
    }        

    // Inspect context's inflight packets and ensure that only pid 3 is left.

    // Check size of inflight elements for ctx, which should be 1 (pid 3)
    if (pub_packet_list_size(&ctx.inflight) != 0) {
        printf("Failed pub test 9.2. Wanted size 0, got %d\n",
               pub_packet_list_size(&ctx.inflight));
        exit(255);
    }        

    // Send the rest of the packags.
    pack = pub_next_queued_packet(&ctx);
    if (pack->pid != 4) {
        printf("Failed pub test 10.1. Wanted packet id 4, got %lu\n",
               pack->pid);
        exit(255);
    }
    pub_packet_sent(&ctx, pack, rmc_usec_monotonic_timestamp());

    pack = pub_next_queued_packet(&ctx);
    if (pack->pid != 5) {
        printf("Failed pub test 10.2. Wanted packet id 5, got %lu\n",
               pack->pid);
        exit(255);
    }
    pub_packet_sent(&ctx, pack, rmc_usec_monotonic_timestamp());
    
    pack = pub_next_queued_packet(&ctx);
    if (pack->pid != 6) {
        printf("Failed pub test 10.3. Wanted packet id 6, got %lu\n",
               pack->pid);
        exit(255);
    }
    pub_packet_sent(&ctx, pack, rmc_usec_monotonic_timestamp());
    
    pack = pub_next_queued_packet(&ctx);
    if (pack->pid != 7) {
        printf("Failed pub test 10.4. Wanted packet id 7, got %lu\n",
               pack->pid);
        exit(255);
    }
    pub_packet_sent(&ctx, pack, rmc_usec_monotonic_timestamp());

    // Ack all the packages in a semi-random order
    pub_packet_ack(&sub1, 5, 0);
    pub_packet_ack(&sub2, 5, 0);
    pub_packet_ack(&sub3, 5, 0);

    pub_packet_ack(&sub1, 7, 0);
    pub_packet_ack(&sub2, 7, 0);
    pub_packet_ack(&sub3, 7, 0);

    pub_packet_ack(&sub1, 6, 0);
    pub_packet_ack(&sub2, 6, 0);
    pub_packet_ack(&sub3, 6, 0);

    pub_packet_ack(&sub1, 4, 0);
    pub_packet_ack(&sub2, 4, 0);
    pub_packet_ack(&sub3, 4, 0);

    // Check that everything is empty
    if (pub_packet_list_size(&ctx.inflight) != 0) {
        printf("Failed pub test 11.1. Wanted size 0, got %d\n",
               pub_packet_list_size(&ctx.inflight));
        exit(255);
    }        
    
    if (pub_packet_list_size(&ctx.queued) != 0) {
        printf("Failed pub test 11.2. Wanted size 0, got %d\n",
               pub_packet_list_size(&ctx.queued));
        exit(255);
    }        
    
    
    if (pub_packet_list_size(&sub1.inflight) != 0) {
        printf("Failed pub test 11.3. Wanted size 0, got %d\n",
               pub_packet_list_size(&sub1.inflight));
        exit(255);
    }        
    
    if (pub_packet_list_size(&sub2.inflight) != 0) {
        printf("Failed pub test 11.4. Wanted size 0, got %d\n",
               pub_packet_list_size(&sub2.inflight));
        exit(255);
    }        
    
    if (pub_packet_list_size(&sub3.inflight) != 0) {
        printf("Failed pub test 11.5. Wanted size 0, got %d\n",
               pub_packet_list_size(&sub3.inflight));
        exit(255);
    }     

    

    // Reset next_pid to make testing easier.
    ctx.next_pid = 1;
    //
    // Check that collection of timed out packages works.
    //
    if ((pid = pub_queue_packet(&ctx, "1", 2, user_data_nil())) != 1) {
        printf("Failed pub test 12.1. Wanted pid 1, got %lu\n",
               pid);
        exit(255);
    }            
    // Queue integrity has already been tested. Trust rest of pids to
    // be 2-6.
    pub_queue_packet(&ctx, "2", 2, user_data_nil());
    pub_queue_packet(&ctx, "3", 2, user_data_nil());
    pub_queue_packet(&ctx, "4", 2, user_data_nil());
    pub_queue_packet(&ctx, "5", 2, user_data_nil());
    pub_queue_packet(&ctx, "6", 2, user_data_nil());

    // Send each packet in turn, increasing time stamp
    // by one for each packet
    pack = pub_next_queued_packet(&ctx);
    pub_packet_sent(&ctx, pack, 1);

    pack = pub_next_queued_packet(&ctx);
    pub_packet_sent(&ctx, pack, 2);

    pack = pub_next_queued_packet(&ctx);
    pub_packet_sent(&ctx, pack, 3);

    pack = pub_next_queued_packet(&ctx);
    pub_packet_sent(&ctx, pack, 4);

    pack = pub_next_queued_packet(&ctx);
    pub_packet_sent(&ctx, pack, 5);

    pack = pub_next_queued_packet(&ctx);
    pub_packet_sent(&ctx, pack, 6);
    
    // All subs will have p1 acked
    //
    // Inflight pids after ack:
    // sub1: - 2 3 4 5 6
    // sub2: - 2 3 4 5 6
    // sub3: - 2 3 4 5 6
    //
    pub_packet_ack(&sub1, 1, 0);
    pub_packet_ack(&sub2, 1, 0);
    pub_packet_ack(&sub3, 1, 0);

    // Sub3 will have all packes acked
    //
    // After:
    // sub1: - 2 3 4 5 6
    // sub2: - 2 3 4 5 6
    // sub3: - - - - - -
    //
    pub_packet_ack(&sub3, 2, 0);
    pub_packet_ack(&sub3, 3, 0);
    pub_packet_ack(&sub3, 4, 0);
    pub_packet_ack(&sub3, 5, 0);
    pub_packet_ack(&sub3, 6, 0);

    // Ack p2 and p3 for sub2
    //
    // After:
    // sub1: - 2 3 4 5 6
    // sub2: - - - 4 5 6
    // sub3: - - - - - -
    pub_packet_ack(&sub2, 2, 0);
    pub_packet_ack(&sub2, 3, 0);

    // Get all packets sent >= 2 usecs ago.
    // Expected hits of subscribers:
    // sub1 - 2,3,4
    // sub2 - 4
    pub_sub_list_init(&sub_lst, 0,0,0);
    pub_get_timed_out_subscribers(&ctx, 6, 2, &sub_lst);

    // sub1 and sub2 should be in the list
    if (pub_sub_list_size(&sub_lst) != 2) {
        printf("Failed pub test 12.2. Wanted size 2, got %d\n",
               pub_sub_list_size(&sub_lst));
        exit(255);
    }

    //
    // Check Sub1
    // 
    sptr1 = pub_sub_list_head(&sub_lst)->data;
    if (sptr1 == &sub2) {
        printf("Failed pub test 12.3. Wanted sub1, got sub2\n");
        exit(255);
    }

    if (sptr1 == &sub3) {
        printf("Failed pub test 12.4. Wanted sub1, got sub3\n");

        exit(255);
    }

    if (sptr1 != &sub1) {
        printf("Failed pub test 12.5. Wanted sub1, got weird %p\n",
               sptr1);
        exit(255);
    }

    //
    // Check Sub2
    // 
    sptr2 = pub_sub_list_tail(&sub_lst)->data;
    if (sptr2 == &sub3) {
        printf("Failed pub test 13.1. Wanted sub2, got sub3\n");
        exit(255);

    }

    if (sptr2 == &sub1) {
        printf("Failed pub test 13.2. Wanted sub2, got sub1\n");

        exit(255);
    }

    if (sptr2 != &sub2) {
        printf("Failed pub test 13.3 Wanted sub2, got weird %p\n",
               sptr1);
        exit(255);
    }

    // Get all packets sent >= 3 usecs ago.
    // Expected hits of subscribers:
    // sub1 - 2,3
    pub_sub_list_empty(&sub_lst);
    pub_get_timed_out_subscribers(&ctx, 6, 3, &sub_lst);

    // sub1 and sub2 should be in the list
    if (pub_sub_list_size(&sub_lst) != 1) {
        printf("Failed pub test 14.1. Wanted size 1, got %d\n",
               pub_sub_list_size(&sub_lst));
        exit(255);
    }

    //
    // Check Sub1
    // 
    sptr1 = pub_sub_list_head(&sub_lst)->data;
    if (sptr1 == &sub2) {
        printf("Failed pub test 14.2. Wanted sub1, got sub2\n");
        exit(255);
    }

    if (sptr1 == &sub3) {
        printf("Failed pub test 14.3. Wanted sub1, got sub3\n");

        exit(255);
    }

    if (sptr1 != &sub1) {
        printf("Failed pub test 14.4. Wanted sub1, got weird %p\n",
               sptr1);
        exit(255);
    }

    //
    // Test oldest inflight packets
    // 
    pub_get_oldest_unackowledged_packet(&ctx, &ts);

    if (ts == -1) {
        printf("Failed pub test 15.1. Wanted oldest subscriber sent ts. Got nothing\n");
        exit(255);
    }

    // Oldest pid is 2.
    //
    // sub1: - 2 3 4 5 6
    // sub2: - - - 4 5 6
    // sub3: - - - - - -
    if (ts != 2) {
        printf("Failed pub test 15.5. Wanted ts 2, got %lu\n",
               ts);
        exit(255);
        
    }
    pub_packet_ack(&sub1, 2, 0);
    pub_packet_ack(&sub1, 3, 0);
    pub_packet_ack(&sub1, 4, 0);
    pub_packet_ack(&sub1, 5, 0);
    pub_packet_ack(&sub1, 6, 0);

    pub_packet_ack(&sub2, 4, 0);
    pub_packet_ack(&sub2, 5, 0);
    pub_packet_ack(&sub2, 6, 0);
}

