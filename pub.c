// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "rmc_pub.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

// TODO: Ditch malloc and use a stack-based alloc/free setup that operates
//       on static-sized heap memory allocated at startup. 
static pending_packet_t* _alloc_pending_packet()
{
    pending_packet_t* res = (pending_packet_t*) malloc(sizeof(pending_packet_t));

    assert(res);
    return res;
}

static void _free_pending_packet(pending_packet_t* ppack)
{
    assert(ppack);
    free((void*) ppack);
}


// TODO: Ditch malloc and use a stack-based alloc/free setup that operates
//       on static-sized heap memory allocated at startup. 
static pub_subscriber_t* _alloc_subscriber()
{
    pub_subscriber_t* res = (pub_subscriber_t*) malloc(sizeof(pub_subscriber_t));

    assert(res);
    return res;
}

static void _free_subscriber(pub_subscriber_t* sub)
{
    assert(sub);
    free((void*) sub);
}

static packet_id_t _next_pid(pub_context_t* ctx)
{
    assert(ctx);

    return ctx->next_pid++;
}

       
void pub_init_context(pub_context_t* ctx,
                      void (*payload_free)(void*, payload_len_t))
{
    assert(ctx);

    list_init(&ctx->subscribers);
    list_init(&ctx->queued);
    list_init(&ctx->inflight);
    ctx->payload_free = payload_free;
    ctx->next_pid = 1;

}


void pub_init_subscriber(pub_subscriber_t* sub, pub_context_t* ctx)
{
    assert(sub);
    assert(ctx);

    sub->context = ctx;
    list_init(&sub->inflight);
    list_push_tail(&ctx->subscribers, LIST_DATA(sub));
}


packet_id_t pub_queue_packet(pub_context_t* ctx,
                             void* payload,
                             payload_len_t payload_len)
{
    list_node_t *node = 0;
    pending_packet_t* ppack = 0;
    assert(ctx);
    assert(payload);

    ppack = _alloc_pending_packet();

    ppack->pid = _next_pid(ctx);
    ppack->payload = payload;
    ppack->payload_len = payload_len;
    ppack->ref_count = 0;
    ppack->send_ts = 0; // Will be set by pub_packet_sent()

    // Insert into ctx->queued, sorted in descending order.
    // We will pop off this list at the tail to get the next
    // node to send in pub_next_queued_packet().
    //
    // Set parent node to the list_node_t representing
    // the pending packet in ctx->queed for quick unlinking.
    //
    ppack->parent_node = 
        list_insert_sorted(&ctx->queued,
                           LIST_DATA(ppack),
                           lambda(int, (list_data_t n_dt, list_data_t o_dt) {
                                   pending_packet_t* n_pend = n_dt.data;
                                   pending_packet_t* o_pend = o_dt.data;
                                   (n_pend->pid > o_pend->pid)?1:
                                       ((n_pend->pid < o_pend->pid)?-1:
                                        0);
                               }
                               ));

    
    return ppack->pid;
}

pending_packet_t* pub_next_queued_packet(pub_context_t* ctx)
{
    assert(ctx);
    
    return (pending_packet_t*) list_tail(&ctx->queued)->data.data;
}

void pub_packet_sent(pub_context_t* ctx,
                     pending_packet_t* ppack,
                     usec_timestamp_t send_ts)
{
    list_node_t* sub_node = 0; // Subscribers in ctx,
    list_node_t* ppack_node = 0;

    assert(ctx);

    // Record the usec timestamp when it was sent.
    ppack->send_ts = send_ts;

    // Unlink the node from queued packets in our context.
    // ppack->parent will still be allocated and can be reused
    // when we insert the ppack into the inflight packets
    // of context
    list_unlink(ppack->parent_node);
    
    // Insert existing ppack->parent list_node_t struct into
    // the context's inflight packets. 
    // Sorted on ascending pid.
    //
    list_insert_sorted_node(&ctx->inflight,
                            ppack->parent_node,
                            lambda(int, (list_data_t n_dt, list_data_t o_dt) {
                                    pending_packet_t* n_pend = n_dt.data;
                                    pending_packet_t* o_pend = o_dt.data;
                                    if (n_pend->pid > o_pend->pid)
                                        return 1;

                                    if (n_pend->pid < o_pend->pid)
                                        return -1;

                                    return 0;
                                }
                                ));

    // Traverse all subscribers and insert ppack into their
    // inflight list.
    // List is sorted on ascending order.
    //
    sub_node = list_head(&ctx->subscribers);
    while(sub_node) {
        pub_subscriber_t* sub = (pub_subscriber_t*) sub_node->data.data;

        // Insert the new pending_packet_t in the descending
        // packet_id sorted list of the subscriber's inflight packets.
        list_insert_sorted(&sub->inflight,
                           LIST_DATA(ppack),
                           lambda(int, (list_data_t n_dt, list_data_t o_dt) {
                                   pending_packet_t* n_pend = n_dt.data;
                                   pending_packet_t* o_pend = o_dt.data;
                                   if (n_pend->pid < o_pend->pid)
                                       return -1;

                                   if (n_pend->pid > o_pend->pid)
                                       return 1;

                                   return 0;
                               }
                               ));
        ppack->ref_count++;
        sub_node = list_next(sub_node);
    }
}


void pub_packet_ack(pub_subscriber_t* sub, packet_id_t pid)
{
    list_node_t* node = 0; // Packets
    pending_packet_t* ppack = 0;

    assert(sub);

    // Traverse all inflight packets of the subscriber and find the
    // one matching pid. We do this from the rear since we are more likely
    // to get an ack on an older packet with a lower pid than a newer one
    node = list_tail(&sub->inflight);

    while(node) {
        ppack = node->data.data;

        if (ppack->pid == pid)
            break;

        node = list_prev(node);
    }

    // No inflight packet found for the ack.
    // This should never happen since we get the acks
    // via TCP that cannot ack the same packet twice.
    if (!node) {
        printf("pub_packet_ack(%lu): No matching packet found in subscriber inflight packets.\n", pid);
        exit(255); // TOOD: Handle at calling level.
    }

    // Delete from subscriber's inflight packets
    list_delete(node);

    // Decrease ref counter
    ppack->ref_count--;

    // If ref_count is zero, then all subscribers have acked the
    // packet, which can now be removed from the pub_context_t::pending
    // list. ppack->parent_node points to the list_node_t struct in the pending
    // list that is to be unlinked and deleted.
    //
    if (!ppack->ref_count) {
        list_delete(ppack->parent_node);

        // Free data using function provided to pub_init_context
        (*sub->context->payload_free)(ppack->payload, ppack->payload_len);

        // Delete the ppack.
        _free_pending_packet(ppack);
    }
}


#ifdef INCLUDE_TEST

static void _test_pub_free(void* payload, payload_len_t plen)
{
    // We are not allocating payload from heap.
    return;
}

static uint8_t _test_print_pending(list_node_t* node, void* dt)
{
    pending_packet_t* pack = (pending_packet_t*) node->data.data;
    int indent = (int) (uint64_t) dt;

    printf("%*cPending Packet  %p\n", indent*2, ' ', pack);
    printf("%*c  PID             %lu\n", indent*2, ' ', pack->pid);
    printf("%*c  Reference count %d\n", indent*2, ' ', pack->ref_count);
    printf("%*c  Parent node     %p\n", indent*2, ' ', pack->parent_node);
    printf("%*c  Payload Length  %d\n", indent*2, ' ', pack->payload_len);
    putchar('\n');
    return 1;
}


static uint8_t _test_print_subscriber(list_node_t* node, void* dt)
{
    pub_subscriber_t* sub = (pub_subscriber_t*) node->data.data;
    int indent = (int) (uint64_t) dt;

    printf("%*cSubscriber %p\n", indent*2, ' ', sub);
    if (list_size(&sub->inflight) > 0) {
        printf("%*cInflight packets:\n", indent*3, ' ');
        list_for_each(&sub->inflight, _test_print_pending, (void*) ((uint64_t)indent + 2));
    } else
        printf("%*cInflight packets: [None]\n", indent*2, ' ');

    putchar('\n');
        
    return 1;
}

void test_print_context(pub_context_t* ctx)
{
    printf("Context           %p\n", ctx);
    printf("Next PID          %lu\n", ctx->next_pid);
    if (list_size(&ctx->queued) > 0) {
        printf("Queued Packets:\n");
        list_for_each(&ctx->queued, _test_print_pending, (void*) (uint64_t) 1);
    } else
        printf("Queued Packets: [None]\n");

    if (list_size(&ctx->inflight) > 0) {
        printf("\nInflight Packets:\n");
        list_for_each(&ctx->inflight, _test_print_pending, (void*) (uint64_t) 1);
    } else
        printf("Queued Packets: [None]\n");

    if (list_size(&ctx->subscribers) > 0) {
        printf("\nSubscribers:\n");
        list_for_each(&ctx->subscribers, _test_print_subscriber, (void*) (uint64_t) 1);
    } else
        printf("Queued Packets: [None]\n");

}

void test_pub(void)
{
    pub_context_t ctx;
    pub_subscriber_t sub1;
    pub_subscriber_t sub2;
    pub_subscriber_t sub3;

    pending_packet_t* pack;
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

    
    if (list_size(&ctx.queued) != 7) {
        printf("Failed pub test 1.2. Wanted size 7, got %d\n",
               list_size(&ctx.queued));
        exit(0);
    }

    if (list_size(&ctx.inflight) != 0) {
        printf("Failed pub test 1.3. Wanted size 0, got %d\n",
               list_size(&ctx.inflight));
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
    if (list_size(&ctx.queued) != 4) {
        printf("Failed pub test 3.1. Wanted size , got %d\n",
               list_size(&ctx.queued));
        exit(0);
    }

    // Check that we have three inflight packets
    if (list_size(&ctx.inflight) != 3) {
        printf("Failed pub test 3.2. Wanted size 3, got %d\n",
               list_size(&ctx.inflight));
        exit(0);
    }

    //
    // Check that all subscribers have three inflight packets.
    //
    if (list_size(&sub1.inflight) != 3) {
        printf("Failed pub test 4.1. Wanted size 3, got %d\n",
               list_size(&sub1.inflight));
        exit(0);
    }

    if (list_size(&sub2.inflight) != 3) {
        printf("Failed pub test 4.2. Wanted size 3, got %d\n",
               list_size(&sub3.inflight));
        exit(0);
    }

    if (list_size(&sub3.inflight) != 3) {
        printf("Failed pub test 4.3. Wanted size 3, got %d\n",
               list_size(&sub3.inflight));
        exit(0);
    }


    // Check that sub is in descending order.
    pack = (pending_packet_t*) list_head(&sub1.inflight)->data.data;

    if (pack->pid != 3) {
        printf("Failed pub test 5.1. Wanted pid 3, got %lu\n",
               pack->pid);
        exit(0);
    }

    pack = (pending_packet_t*) list_tail(&sub1.inflight)->data.data;

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
    if (list_size(&sub1.inflight) != 2) {
        printf("Failed pub test 6.1. Wanted size 2, got %d\n",
               list_size(&sub1.inflight));
        exit(0);
    }

    // Inspect he two elements left and ensure that they are correct.
    pack = (pending_packet_t*) list_head(&sub1.inflight)->data.data;
    if (pack->pid != 3) {
        printf("Failed pub test 6.2. Wanted pid 2, got %lu\n",
               pack->pid);
        exit(0);
    }

    pack = (pending_packet_t*) list_tail(&sub1.inflight)->data.data;
    if (pack->pid != 2) {
        printf("Failed pub test 6.3. Wanted size 3, got %lu\n",
               pack->pid);
        exit(0);
    }

    // Inspect the element in the context's inflight queue
    // It should be tail in the queue since we sort on descending.
    pack = (pending_packet_t*) list_tail(&ctx.inflight)->data.data;
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
    if (list_size(&ctx.inflight) != 2) {
        printf("Failed pub test 7.1. Wanted size 2, got %d\n",
               list_size(&ctx.inflight));
        exit(0);
    }        

    // Check that the first inflight package is pid 2
    pack = (pending_packet_t*) list_tail(&ctx.inflight)->data.data;
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
    if (list_size(&sub2.inflight) != 1) {
        printf("Failed pub test 8.1. Wanted size 1, got %d\n",
               list_size(&sub2.inflight));
        exit(0);
    }        

    // Inspect sub2 to see that its only remaining inflight packet is pid 2
    pack = (pending_packet_t*) list_head(&sub2.inflight)->data.data;
    if (pack->pid != 2) {
        printf("Failed pub test 8.2. Wanted size 2, got %lu\n",
               pack->pid);
        exit(0);
    }

    // Inspect context's inflight packets and ensure that only pid 3 is left.

    // Check size of inflight elements for ctx, which should be 1 (pid 3)
    if (list_size(&ctx.inflight) != 1) {
        printf("Failed pub test 8.3. Wanted size 1, got %d\n",
               list_size(&ctx.inflight));
        exit(0);
    }        

    // Inspect ctx inflighjt to see that its only remaining inflight
    // packet is pid 2
    pack = (pending_packet_t*) list_head(&ctx.inflight)->data.data;
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
    if (list_size(&sub3.inflight) != 0) {
        printf("Failed pub test 9.1. Wanted size 0, got %d\n",
               list_size(&sub3.inflight));
        exit(0);
    }        

    // Inspect context's inflight packets and ensure that only pid 3 is left.

    // Check size of inflight elements for ctx, which should be 1 (pid 3)
    if (list_size(&ctx.inflight) != 0) {
        printf("Failed pub test 9.2. Wanted size 0, got %d\n",
               list_size(&ctx.inflight));
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
    if (list_size(&ctx.inflight) != 0) {
        printf("Failed pub test 11.1. Wanted size 0, got %d\n",
               list_size(&ctx.inflight));
        exit(0);
    }        
    
    if (list_size(&ctx.queued) != 0) {
        printf("Failed pub test 11.2. Wanted size 0, got %d\n",
               list_size(&ctx.queued));
        exit(0);
    }        
    
    
    if (list_size(&sub1.inflight) != 0) {
        printf("Failed pub test 11.3. Wanted size 0, got %d\n",
               list_size(&sub1.inflight));
        exit(0);
    }        
    
    if (list_size(&sub2.inflight) != 0) {
        printf("Failed pub test 11.4. Wanted size 0, got %d\n",
               list_size(&sub2.inflight));
        exit(0);
    }        
    
    if (list_size(&sub3.inflight) != 0) {
        printf("Failed pub test 11.5. Wanted size 0, got %d\n",
               list_size(&sub3.inflight));
        exit(0);
    }        
    
}
#endif

