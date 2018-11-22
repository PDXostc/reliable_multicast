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

static void add_packet(sub_packet_list_t* lst, packet_id_t pid)
{
    sub_packet_t *new_pack = (sub_packet_t*) malloc(sizeof(sub_packet_t));

    memset(new_pack, 0, sizeof(sub_packet_t));
    new_pack->pid = pid;
    sub_packet_list_push_tail(lst, new_pack);
}

static void reset_list(sub_packet_list_t* lst)
{
    sub_packet_t *pack = 0;
    while(sub_packet_list_pop_head(lst, &pack))
        free(pack);
}

void test_packet_interval()
{
    sub_packet_list_t lst;
    sub_packet_node_t* node;
    packet_interval_t intv = { .first_pid = 0, .last_pid = 0 };
    packet_id_t pid = 0;

    sub_packet_list_init(&lst, 0, 0, 0);
    add_packet(&lst, 1);
    add_packet(&lst, 2);
    add_packet(&lst, 3);
    add_packet(&lst, 4);
    add_packet(&lst, 5);

    add_packet(&lst, 7);
    add_packet(&lst, 8);
    add_packet(&lst, 9);

    add_packet(&lst, 223);
    add_packet(&lst, 224);

    add_packet(&lst, 226);

    node = sub_packet_list_head(&lst);

    node = sub_get_packet_interval(node, &intv);
    if (intv.first_pid != 1 || intv.last_pid != 5) {
        printf("Failed interval test 1.1. Wanted 1:5. Got %lu:%lu\n",
               intv.first_pid, intv.last_pid);
        exit(255);
    }

    intv.first_pid = 0;
    intv.last_pid = 0;
    node =sub_get_packet_interval(node, &intv);
    if (intv.first_pid != 7 || intv.last_pid != 9) {
        printf("Failed interval test 1.2. Wanted 7:9. Got %lu:%lu\n",
               intv.first_pid, intv.last_pid);
        exit(255);
    }

    intv.first_pid = 0;
    intv.last_pid = 0;
    node =sub_get_packet_interval(node, &intv);
    if (intv.first_pid != 223 || intv.last_pid != 224) {
        printf("Failed interval test 1.3. Wanted 223:224. Got %lu:%lu\n",
               intv.first_pid, intv.last_pid);
        exit(255);
    }

    intv.first_pid = 0;
    intv.last_pid = 0;
    node =sub_get_packet_interval(node, &intv);
    if (intv.first_pid != 226 || intv.last_pid != 226) {
        printf("Failed interval test 1.4. Wanted 226:226. Got %lu:%lu\n",
               intv.first_pid, intv.last_pid);
        exit(255);
    }

    reset_list(&lst);
    
    add_packet(&lst, 100);
    
    intv.first_pid = 0;
    intv.last_pid = 0;
    node = sub_packet_list_head(&lst);
    node =sub_get_packet_interval(node, &intv);
    if (intv.first_pid != 100 || intv.last_pid != 100) {
        printf("Failed interval test 1.1. Wanted 100:100. Got %lu:%lu\n",
               intv.first_pid, intv.last_pid);
        exit(255);
    }

    reset_list(&lst);
    
    add_packet(&lst, 300);
    add_packet(&lst, 301);
    node = sub_packet_list_head(&lst);
    
    intv.first_pid = 0;
    intv.last_pid = 0;
    node =sub_get_packet_interval(node, &intv);
    if (intv.first_pid != 300 || intv.last_pid != 301) {
        printf("Failed interval test 1.1. Wanted 300-103. Got %lu %lu\n",
               intv.first_pid, intv.last_pid);
        exit(255);
    }
}

void test_packet_intervals()
{
    sub_packet_list_t lst;
    intv_list_t intv_lst;
    intv_node_t* node;
    packet_interval_t intv = { .first_pid = 0, .last_pid = 0};
    uint32_t res = 0;
    
    sub_packet_list_init(&lst, 0, 0, 0);
    intv_list_init(&intv_lst, 0, 0, 0);
    add_packet(&lst, 1);
    add_packet(&lst, 2);
    add_packet(&lst, 3);
    add_packet(&lst, 4);
    add_packet(&lst, 5);

    add_packet(&lst, 7);

    add_packet(&lst, 223);
    add_packet(&lst, 224);

    add_packet(&lst, 226);

    // Grab all intervals and check context
    res =sub_get_packet_intervals(&lst, &intv_lst);

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
