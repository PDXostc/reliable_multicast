// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "interval.h"

#include <stdio.h>
#include <stdlib.h>
void test_packet_interval()
{
    pid_list_t p1;
    pid_node_t* node;
    packet_interval_t intv = { .first_pid = 0, .last_pid = 0 };
    packet_id_t pid = 0;

    pid_list_init(&p1, 0, 0, 0);
    pid_list_push_tail(&p1, 1);
    pid_list_push_tail(&p1, 2);
    pid_list_push_tail(&p1, 3);
    pid_list_push_tail(&p1, 4);
    pid_list_push_tail(&p1, 5);

    pid_list_push_tail(&p1, 7);
    pid_list_push_tail(&p1, 8);
    pid_list_push_tail(&p1, 9);

    pid_list_push_tail(&p1, 223);
    pid_list_push_tail(&p1, 224);

    pid_list_push_tail(&p1, 226);

    node = pid_list_head(&p1);

    node = get_packet_interval(node, &intv);
    if (intv.first_pid != 1 || intv.last_pid != 5) {
        printf("Failed interval test 1.1. Wanted 1:5. Got %lu:%lu\n",
               intv.first_pid, intv.last_pid);
        exit(255);
    }

    intv.first_pid = 0;
    intv.last_pid = 0;
    node = get_packet_interval(node, &intv);
    if (intv.first_pid != 7 || intv.last_pid != 9) {
        printf("Failed interval test 1.2. Wanted 7:9. Got %lu:%lu\n",
               intv.first_pid, intv.last_pid);
        exit(255);
    }

    intv.first_pid = 0;
    intv.last_pid = 0;
    node = get_packet_interval(node, &intv);
    if (intv.first_pid != 223 || intv.last_pid != 224) {
        printf("Failed interval test 1.3. Wanted 223:224. Got %lu:%lu\n",
               intv.first_pid, intv.last_pid);
        exit(255);
    }

    intv.first_pid = 0;
    intv.last_pid = 0;
    node = get_packet_interval(node, &intv);
    if (intv.first_pid != 226 || intv.last_pid != 226) {
        printf("Failed interval test 1.4. Wanted 226:226. Got %lu:%lu\n",
               intv.first_pid, intv.last_pid);
        exit(255);
    }

    while(pid_list_pop_head(&p1, &pid));

    pid_list_push_tail(&p1, 100);
    
    intv.first_pid = 0;
    intv.last_pid = 0;
    node = pid_list_head(&p1);
    node = get_packet_interval(node, &intv);
    if (intv.first_pid != 100 || intv.last_pid != 100) {
        printf("Failed interval test 1.1. Wanted 100:100. Got %lu:%lu\n",
               intv.first_pid, intv.last_pid);
        exit(255);
    }

    while(pid_list_pop_head(&p1, &pid));

    pid_list_push_tail(&p1, 300);
    pid_list_push_tail(&p1, 301);
    node = pid_list_head(&p1);
    
    intv.first_pid = 0;
    intv.last_pid = 0;
    node = get_packet_interval(node, &intv);
    if (intv.first_pid != 300 || intv.last_pid != 301) {
        printf("Failed interval test 1.1. Wanted 300-103. Got %lu %lu\n",
               intv.first_pid, intv.last_pid);
        exit(255);
    }
}

void test_packet_intervals()
{
    pid_list_t p1;
    intv_list_t intv_lst;
    intv_node_t* node;
    packet_interval_t intv = { .first_pid = 0, .last_pid = 0};
    uint32_t res = 0;
    
    pid_list_init(&p1, 0, 0, 0);
    intv_list_init(&intv_lst, 0, 0, 0);
    pid_list_push_tail(&p1, 1);
    pid_list_push_tail(&p1, 2);
    pid_list_push_tail(&p1, 3);
    pid_list_push_tail(&p1, 4);
    pid_list_push_tail(&p1, 5);

    pid_list_push_tail(&p1, 7);

    pid_list_push_tail(&p1, 223);
    pid_list_push_tail(&p1, 224);

    pid_list_push_tail(&p1, 226);

    // Grab all intervals and check context
    res = get_packet_intervals(&p1, pid_list_size(&p1), &intv_lst);

    if (res != 9) {
        printf("Failed intervals test 1.1. Wanted 8. Got %u\n", res);
        exit(255);
    }

    node = intv_list_head(&intv_lst);
    intv = node->data;
    if (intv.first_pid != 1 || intv.last_pid != 5) {
        printf("Failed intervals test 1.2. Wanted 1:5. Got %lu:%lu\n",
               intv.first_pid, intv.last_pid);
        exit(255);
    }

    node = intv_list_next(node);
    intv = node->data;
    if (intv.first_pid != 7 || intv.last_pid != 7) {
        printf("Failed intervals test 1.3. Wanted 7:7. Got %lu:%lu\n",
               intv.first_pid, intv.last_pid);
        exit(255);
    }

    node = intv_list_next(node);
    intv = node->data;
    if (intv.first_pid != 223 || intv.last_pid != 224) {
        printf("Failed intervals test 1.4. Wanted 223:224. Got %lu:%lu\n",
               intv.first_pid, intv.last_pid);
        exit(255);
    }

    node = intv_list_next(node);
    intv = node->data;
    if (intv.first_pid != 226 || intv.last_pid != 226) {
        printf("Failed intervals test 1.4. Wanted 226:226. Got %lu:%lu\n",
               intv.first_pid, intv.last_pid);
        exit(255);
    }
}
