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


static uint8_t _test_print_interval(sub_pid_interval_node_t* node, void* dt)
{
    sub_pid_interval_t intv =  node->data;
    int indent = (int) (uint64_t) dt;

    printf("%*cInterval: %lu - %lu\n", indent*2, ' ', intv.first_pid, intv.last_pid);
    return 1;
}

static uint8_t _test_print_interval_list(sub_publisher_t* pub)
{

    puts("Interval:");
    sub_pid_interval_list_for_each(&pub->received_interval, _test_print_interval, (void*) 1);
    return 1;
}


static void add_packet(sub_publisher_t* pub, packet_id_t pid)
{
    sub_packet_received(pub, pid, "", 0, 1, 0, user_data_nil());
}

static void reset_list(sub_packet_list_t* lst)
{
    sub_packet_t *pack = 0;
    while(sub_packet_list_pop_head(lst, &pack))
        free(pack);
}

void test_packet_interval()
{
    sub_publisher_t pub;
    sub_pid_interval_list_t ilst;
    sub_packet_list_t plst;
    sub_pid_interval_node_t* pnode;
    sub_pid_interval_t intv = { .first_pid = 0, .last_pid = 0 };
    packet_id_t pid = 0;

    sub_init_publisher(&pub);

    sub_pid_interval_list_init(&ilst, 0, 0, 0);
    sub_packet_list_init(&plst, 0, 0, 0);

    //
    // Try Single packet
    //

    add_packet(&pub, 100);
    sub_process_received_packets(&pub, &plst);

    if (sub_pid_interval_list_size(&pub.received_interval) != 1) {
        printf("Failed interval test 1.1. Wanted size 1. Got %d\n",
               sub_pid_interval_list_size(&pub.received_interval));
        _test_print_interval_list(&pub);
        exit(255);
    }

    sub_pid_interval_list_pop_head(&pub.received_interval, &intv);

    if (intv.first_pid != 100 || intv.last_pid != 100) {
        printf("Failed interval test 1.2. Wanted 100:100. Got %lu:%lu\n",
               intv.first_pid, intv.last_pid);
        _test_print_interval_list(&pub);
        exit(255);
    }


    sub_reset_publisher(&pub, 0);
    sub_packet_list_empty(&plst);
    sub_pid_interval_list_empty(&ilst);

    //
    // Try multiple intervals
    //
    add_packet(&pub, 4);
    add_packet(&pub, 5);

    add_packet(&pub, 8);
    add_packet(&pub, 9);
    add_packet(&pub, 10);

    add_packet(&pub, 223);
    add_packet(&pub, 224);

    add_packet(&pub, 226);

    //
    // Check integrity of the interval list
    //
    //  4-5
    //  8-10
    //  223-224
    //  226-226

    sub_process_received_packets(&pub, &plst);

    if (sub_pid_interval_list_size(&pub.received_interval) != 4) {
        printf("Failed interval test 1.3. Wanted size 4. Got %d\n",
               sub_pid_interval_list_size(&pub.received_interval));
        _test_print_interval_list(&pub);
        exit(255);
    }


    // Check that intervals are correct.
    pnode = sub_pid_interval_list_head(&pub.received_interval);
    if (pnode->data.first_pid != 4 || pnode->data.last_pid != 5) {
        printf("Failed interval test 1.4. Wanted 3:5. Got %lu:%lu\n",
               pnode->data.first_pid, pnode->data.last_pid);
        _test_print_interval_list(&pub);
        exit(255);
    }

    pnode = sub_pid_interval_list_next(pnode);
    if (pnode->data.first_pid != 8 || pnode->data.last_pid != 10) {
        printf("Failed interval test 1.5. Wanted 8:10. Got %lu:%lu\n",
               pnode->data.first_pid, pnode->data.last_pid);
        _test_print_interval_list(&pub);
        exit(255);
    }

    pnode = sub_pid_interval_list_next(pnode);
    if (pnode->data.first_pid != 223 || pnode->data.last_pid != 224) {
        printf("Failed interval test 1.6. Wanted 223:224. Got %lu:%lu\n",
               pnode->data.first_pid, pnode->data.last_pid);
        _test_print_interval_list(&pub);
        exit(255);
    }

    pnode = sub_pid_interval_list_next(pnode);
    if (pnode->data.first_pid != 226 || pnode->data.last_pid != 226) {
        printf("Failed interval test 1.7. Wanted 226:226. Got %lu:%lu\n",
               pnode->data.first_pid, pnode->data.last_pid);
        _test_print_interval_list(&pub);
        exit(255);
    }


    // Check that we can add a new pid by extending the first interval
    // element from 4-5 to 3-5
    //
    // Before
    //  4-5
    //  8-10
    //  223-224
    //  226-226
    //
    // After
    //  3-5
    //  8-10
    //  223-224
    //  226-226


    add_packet(&pub, 3);
    sub_process_received_packets(&pub, &plst);

    if (sub_pid_interval_list_size(&pub.received_interval) != 4) {
        printf("Failed interval test 1.8. Wanted size 4. Got %d\n",
               sub_pid_interval_list_size(&pub.received_interval));
        _test_print_interval_list(&pub);
        exit(255);
    }

    pnode = sub_pid_interval_list_head(&pub.received_interval);

    if (pnode->data.first_pid != 3 || pnode->data.last_pid != 5) {
        printf("Failed interval test 1.9. Wanted 3:5  Got %lu:%lu\n",
               pnode->data.first_pid, pnode->data.last_pid);
        _test_print_interval_list(&pub);
        exit(255);
    }


    //
    // Check that we can add a new interval element at the very
    // beginning of the interval list.
    //
    // Before
    //  3-5
    //  8-10
    //  223-224
    //  226-226
    //
    // After
    //  1-1
    //  3-5
    //  8-10
    //  223-224
    //  226-226
    add_packet(&pub, 1);
    sub_process_received_packets(&pub, &plst);

    pnode = sub_pid_interval_list_head(&pub.received_interval);

    if (pnode->data.first_pid != 1 || pnode->data.last_pid != 1) {
        printf("Failed interval test 1.10. Wanted 1:1  Got %lu:%lu\n",
               pnode->data.first_pid, pnode->data.last_pid);
        _test_print_interval_list(&pub);
        exit(255);
    }


    //
    // Check that we can merge the two first elements
    // in the interval list
    // Before:
    //  1-1
    //  3-5
    //  8-10
    //  223-224
    //  226-226
    //
    // After:
    //  1-5
    //  8-10
    //  223-224
    //  226-226

    add_packet(&pub, 2);
    sub_process_received_packets(&pub, &plst);

    if (sub_pid_interval_list_size(&pub.received_interval) != 4) {
        printf("Failed interval test 1.11. Wanted size 4. Got %d\n",
               sub_pid_interval_list_size(&pub.received_interval));
        _test_print_interval_list(&pub);
        exit(255);
    }

    pnode = sub_pid_interval_list_head(&pub.received_interval);

    if (pnode->data.first_pid != 1 || pnode->data.last_pid != 5) {
        printf("Failed interval test 1.12. Wanted 1:5  Got %lu:%lu\n",
               pnode->data.first_pid, pnode->data.last_pid);
        _test_print_interval_list(&pub);
        exit(255);
    }


    //
    // Check that we can extend an existing interval at the end.
    //
    // Before
    //  1-5
    //  8-10
    //  223-224
    //  226-226

    //
    // After
    //  1-5
    //  8-11
    //  223-224
    //  226-226
    add_packet(&pub, 11);
    sub_process_received_packets(&pub, &plst);

    if (sub_pid_interval_list_size(&pub.received_interval) != 4) {
        printf("Failed interval test 1.13. Wanted size 4. Got %d\n",
               sub_pid_interval_list_size(&pub.received_interval));
        _test_print_interval_list(&pub);
        exit(255);
    }

    pnode = sub_pid_interval_list_head(&pub.received_interval);
    pnode = sub_pid_interval_list_next(pnode);

    if (pnode->data.first_pid != 8 || pnode->data.last_pid != 11) {
        printf("Failed interval test 1.14. Wanted 6:11  Got %lu:%lu\n",
               pnode->data.first_pid, pnode->data.last_pid);
        _test_print_interval_list(&pub);
        exit(255);
    }

    //
    // Check that we can add three consecutive packets to merge an interval.
    //
    // Before
    //  1-5
    //  8-11
    //  223-224
    //  226-226
    //
    // After
    //  1-11
    //  223-226
    add_packet(&pub, 6);
    add_packet(&pub, 7);
    add_packet(&pub, 225);
    sub_process_received_packets(&pub, &plst);

    if (sub_pid_interval_list_size(&pub.received_interval) != 2) {
        printf("Failed interval test 1.15. Wanted size 2. Got %d\n",
               sub_pid_interval_list_size(&pub.received_interval));
        _test_print_interval_list(&pub);
        exit(255);
    }

    // Check that intervals are correct.
    pnode = sub_pid_interval_list_head(&pub.received_interval);
    if (pnode->data.first_pid != 1 || pnode->data.last_pid != 11) {
        printf("Failed interval test 1.16. Wanted 3:5. Got %lu:%lu\n",
               pnode->data.first_pid, pnode->data.last_pid);
        _test_print_interval_list(&pub);
        exit(255);
    }

    pnode = sub_pid_interval_list_next(pnode);
    if (pnode->data.first_pid != 223 || pnode->data.last_pid != 226) {
        printf("Failed interval test 1.17. Wanted 8:10. Got %lu:%lu\n",
               pnode->data.first_pid, pnode->data.last_pid);
        _test_print_interval_list(&pub);
        exit(255);
    }

}
