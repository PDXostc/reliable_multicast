// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)
// Trivial double linked list.

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

typedef uint32_t packet_id_t;

#include "rmc_list.h"
#include "rmc_list_template.h"

RMC_LIST(test_list_t, test_node_t, packet_id_t)


RMC_LIST_IMPL(test_list_t, test_node_t, packet_id_t)


void test_dump_list(test_list_t* list)
{
    test_node_t* node = test_list_t_head(list);

    printf("LIST: Element count: %d\n", test_list_t_size(list));
    while(node) {
        printf("      node[%p] data[%d]\n",
               node,  node->data);
        node = test_list_t_next(node);
    }
}

static uint8_t _test_sequence(test_list_t* list, packet_id_t start, packet_id_t stop)
{
    test_node_t* node = 0;
    packet_id_t pid = start;

    // Traverse forward
    node = test_list_t_head(list);
    while(node) {
        if (node->data != pid) {
            printf("Fwd Sequence test [%d-%d]. Wanted %d. Got %d\n",
                   start, stop, pid, node->data);
            return 1;
        }
        node = test_list_t_next(node);
        if (start < stop)
            pid++;
        else
            pid--;
    }

    if (start < stop)
        pid--;
    else
        pid++;

    if (pid != stop) {
        printf("Fwd Sequence test [%d-%d]. Wanted final %d. Got %d\n",
               start, stop, pid, node->data);
        return 2;
    }

    // Traverse backward
    node = test_list_t_tail(list);
    pid = stop;
    while(node) {
        if (node->data != pid) {
            printf("Bwd Sequence test [%d-%d]. Wanted %d. Got %d\n",
                   start, stop, pid, node->data);
            return 3;
        }
        node = test_list_t_prev(node);
        if (start < stop)
            pid--;
        else
            pid++;
    }

    if (start < stop)
        pid++;
    else
        pid--;

    if (pid != start) {
        printf("Bwd Sequence test [%d-%d]. Wanted final %d. Got %d\n",
               start, stop, pid, node->data);
        return 4;
    }

    return 0;
}

static int _compare_pid(packet_id_t existing_pid, packet_id_t new_pid)
{
    if (existing_pid > new_pid)
        return 1;

    if (existing_pid < new_pid)
        return -1;

    return 0;

}

void test_list()
{
    test_list_t p1;
    test_node_t* node;
    packet_id_t pid = 1;

    test_list_t_init(&p1, 0, 0, 0);

    // 1
    test_list_t_push_tail(&p1, 1);
    if (_test_sequence(&p1, 1, 1)) {
        puts("Failed list test 1.1.\n");
        exit(0);
    }

    // 2
    test_list_t_push_tail(&p1, 2);
    if (_test_sequence(&p1, 1, 2)) {
        puts("Failed list test 1.2.\n");
        exit(0);
    }

    // 3
    test_list_t_push_tail(&p1, 3);
    if (_test_sequence(&p1, 1, 3)) {
        puts("Failed list test 1.3.\n");
        exit(0);
    }

    // 4
    test_list_t_push_tail(&p1, 4);
    if (_test_sequence(&p1, 1, 4)) {
        puts("Failed list test 1.4.\n");
        exit(0);
    }

    // 5
    test_list_t_push_tail(&p1, 5);
    if (_test_sequence(&p1, 1, 5)) {
        puts("Failed list test 1.5.\n");
        exit(0);
    }

    // 6
    test_list_t_push_tail(&p1, 6);
    if (_test_sequence(&p1, 1, 6)) {
        puts("Failed list test 1.6.\n");
        exit(0);
    }


    // Insert in middle of list.
    node = test_list_t_head(&p1);  // pid == 1
    node = test_list_t_next(node); // pid == 2
    node = test_list_t_next(node); // pid == 3
    test_list_t_insert_after(node, 31);

    // Validate list
    if (node->data != 3) {
        printf("Failed list test 2.1. Wanted 3 Got %d\n",
               node->data);
        exit(0);
    }

    if (test_list_t_next(node)->data != 31) {
        printf("Failed list test 2.2. Wanted 31 Got %d\n",
               node->data);
        exit(0);
    }

    if (test_list_t_next(test_list_t_next(node))->data != 4) {
        printf("Failed list test 2.3. Wanted 4 Got %d\n",
               node->data);
        exit(0);
    }

    // Delete the element we just put in
    node = test_list_t_next(node);
    test_list_t_delete(node);

    if (_test_sequence(&p1, 1, 6)) {
        puts("Failed list test 3.1.\n");
        exit(0);
    }

    // Delete tail element
    test_list_t_delete(test_list_t_tail(&p1));
    if (_test_sequence(&p1, 1, 5)) {
        puts("Failed list test 3.2.\n");
        exit(0);
    }

    // Delete head element
    test_list_t_delete(test_list_t_head(&p1));
    if (_test_sequence(&p1, 2, 5)) {
        puts("Failed list test 3.3.\n");
        exit(0);
    }

    //
    // Test sorted by pid
    //
    while(test_list_t_size(&p1))
        test_list_t_pop_head(&p1);


    test_list_t_insert_sorted(&p1, 2, _compare_pid);
    if (_test_sequence(&p1, 2, 2)) {
        puts("Failed list test 4.1.\n");
        exit(0);
    }

    test_list_t_insert_sorted(&p1, 1, _compare_pid);
    if (_test_sequence(&p1, 2, 1)) {
        puts("Failed list test 4.2.\n");
        exit(0);
    }

    test_list_t_insert_sorted(&p1, 3, _compare_pid);
    if (_test_sequence(&p1, 3, 1)) {
        puts("Failed list test 4.3.\n");
        exit(0);
    }

    test_list_t_insert_sorted(&p1, 7, _compare_pid);
    test_list_t_insert_sorted(&p1, 6, _compare_pid);
    test_list_t_insert_sorted(&p1, 5, _compare_pid);

    test_list_t_insert_sorted(&p1, 4, _compare_pid);
    if (_test_sequence(&p1, 7, 1)) {
        puts("Failed list test 4.4.\n");
        exit(0);
    }

    test_list_t_insert_sorted(&p1, 8, _compare_pid);
    if (_test_sequence(&p1, 8, 1)) {
        puts("Failed list test 4.5.\n");
        exit(0);
    }

}
