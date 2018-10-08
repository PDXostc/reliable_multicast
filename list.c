// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)
// Trivial double linked list.

#include <assert.h>
#include <stdlib.h>

#include "rmc_common.h"

#ifdef INCLUDE_TEST
#include <stdio.h>
#endif

// TODO: Ditch malloc and use a stack-based alloc/free setup that operates
//       on static-sized heap memory allocated at startup. 
static list_node_t* _alloc_list_node(void)
{
    list_node_t* res = (list_node_t*) malloc(sizeof(list_node_t));
    assert(res);

    return res;
}

static void _free_list_node(list_node_t* node)
{
    assert(node);
    free((void*) node);
}


void list_init(list_t* list)
{
    list->head = 0;
    list->tail = 0;
    list->elem_count = 0;
}

list_node_t* list_head(list_t* list)
{
    assert(list);

    return list->head;
}

list_node_t* list_tail(list_t* list)
{
    assert(list);

    return list->tail;
}

list_node_t* list_prev(list_node_t* node)
{
    if (node)
        return node->prev;

    return 0;
}

list_node_t* list_next(list_node_t* node)
{
    if (node)
        return node->next;

    return 0;
}


uint32_t list_size(list_t* list)
{
    assert(list);

    return list->elem_count;
}


list_node_t* list_push_head_node(list_t* list, list_node_t* node) 
{ 
    assert(list);
    assert(node);
  
    node->next = list->head; 
    node->prev = 0; 
    node->list = list;

    if (list->head)
        list->head->prev = node;

    list->head = node;

    if (list->tail == 0) 
        list->tail = node;

    list->elem_count++;
    return node;
}

list_node_t* list_push_head(list_t* list, list_data_t data) 
{ 
    list_node_t* node = _alloc_list_node();

    assert(node);
    node->data = data;
    return list_push_head_node(list, node);
} 

list_node_t* list_push_tail_node(list_t* list, list_node_t* node) 
{ 
    list_node_t* tail = 0;
  
    assert(list);
    if (!node)
        assert(node);

    node->next = 0; 
    node->prev = list->tail; 
    node->list = list;

    if (list->tail != 0) 
        list->tail->next = node;


    list->tail = node;

    if (list->head == 0) 
        list->head = node;

    list->elem_count++;
    return node;
} 

list_node_t* list_push_tail(list_t* list, list_data_t data) 
{ 
    list_node_t* node = _alloc_list_node();

    assert(node);
    node->data = data;
    return list_push_tail_node(list, node);
} 

list_node_t* list_insert_before_node(list_node_t* next, list_node_t* node) 
{ 
    assert(node);
    assert(next != 0);
    assert(next->list != 0);
    
    // Are we at the beginning of the list?
    if (next == list_head(next->list))
        return list_push_head_node(next->list, node);


    node->list = next->list;
    node->prev = next->prev; 

    // Will always be set since we are not at the head of the list.
    node->prev->next = node;

    next->prev = node; 
    node->next = next; 
    
    node->list->elem_count++;
    return node;
}

list_node_t* list_insert_before(list_node_t* next, list_data_t data) 
{ 
    list_node_t* node = 0;
    node = _alloc_list_node(); 
    assert(node);
    node->data = data; 
    return list_insert_before_node(next, node);
}

list_node_t* list_insert_after_node(list_node_t* prev, list_node_t* node) 
{ 
    assert(prev != 0);
    assert(prev->list != 0);

    // Are we at the end of the list?
    if (prev == list_tail(prev->list))
        return list_push_tail_node(prev->list, node);

    node->list = prev->list;
    node->next = prev->next; 

    // Will always be set since we are not at the end of the list.
    node->next->prev = node;

    prev->next = node; 
    node->prev = prev; 

    node->list->elem_count++;
    return node;
}

list_node_t* list_insert_after(list_node_t* next, list_data_t data) 
{ 
    list_node_t* node = 0;
    node = _alloc_list_node(); 
    assert(node);
    node->data = data; 
    return list_insert_after_node(next, node);
}


list_node_t* list_unlink(list_node_t* node)
{
    assert(node);
    assert(node->list);

	if (node->prev)
        node->prev->next = node->next;
   
	if (node->next)
        node->next->prev = node->prev;

    if (node->list->head == node)
        node->list->head = node->next;

    if (node->list->tail == node)
        node->list->tail = node->prev;

    node->list->elem_count--;
    return node;
}


void list_delete(list_node_t* node)
{
    list_unlink(node);
    _free_list_node(node);
}


list_node_t* list_pop_head_node(list_t* list)
{
    assert(list);

    if (!list->head)
        return 0;

    return list_unlink(list->head);
}

list_data_t list_pop_head(list_t* list)
{
    list_data_t data  = { .pid = 0, .data = 0 };
    assert(list);

    if (!list->head)
        return data;

    data = list->head->data;

    list_delete(list->head);
    return data;
}


list_data_t list_pop_tail(list_t* list)
{
    list_data_t data  = { .pid = 0, .data = 0 };

    assert(list);

    if (!list->tail)
        return data;

    data = list->tail->data;

    list_delete(list->tail);
    return data;
}

list_node_t* list_pop_tail_node(list_t* list)
{
    assert(list);

    if (!list->tail)
        return 0;


    return list_unlink(list->tail);
}


void list_for_each(list_t* list,
                   uint8_t (*func)(list_node_t* node, void* user_data),
                   void* user_data)
{
    list_node_t* node = 0;
    assert(list);

    node = list->head;
    while(node && (*func)(node, user_data))
        node = node->next;
}


list_node_t* list_insert_sorted_node(list_t* list,
                                     list_node_t* new_node,
                                     int (*compare_func)(list_data_t new_elem,
                                                         list_data_t existing_elem))
{
    list_node_t* node = 0;

    assert(list);
    node = list_head(list);

    //
    // Traverse list until we find a pid greater than ours.
    //
    while(node) {
        if ((*compare_func)(new_node->data, node->data) >= 0) {
            // Insert before the element that was greater than us.
            return list_insert_before_node(node, new_node);
        }
        node = node->next;
    }

    // Add to end of list.
    return list_push_tail_node(list, new_node);
}

list_node_t* list_insert_sorted(list_t* list,
                                list_data_t new_elem,
                                int (*compare_func)(list_data_t new_elem,
                                                    list_data_t existing_elem))
{
    list_node_t* node = 0;
    list_node_t* new_node = 0;
    assert(list);

    new_node = _alloc_list_node();
    assert(new_node);

    new_node->data = new_elem;
    return list_insert_sorted_node(list, new_node, compare_func);
}

#ifdef INCLUDE_TEST

void test_dump_list(list_t* list)
{
    list_node_t* node = list_head(list);
    
    printf("LIST: Element count: %d\n", list_size(list));
    while(node) {
        printf("      node[%p] pid[%.9lu] data[%p]\n",
               node, node->data.pid, node->data.data);
        node = list_next(node);
    }
}

static uint8_t _test_sequence(list_t* list, packet_id_t start, packet_id_t stop)
{
    list_node_t* node = 0;
    packet_id_t pid = start;
    
    // Traverse forward
    node = list_head(list);
    while(node) {
        if (node->data.pid != pid) {
            printf("Fwd Sequence test [%lu-%lu]. Wanted %lu. Got %lu\n",
                   start, stop, pid, node->data.pid);
            return 1;
        }
        node = list_next(node);
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
        printf("Fwd Sequence test [%lu-%lu]. Wanted final %lu. Got %lu\n",
               start, stop, pid, node->data.pid);
        return 2;
    }

    // Traverse backward
    node = list_tail(list);
    pid = stop;
    while(node) {
        if (node->data.pid != pid) {
            printf("Bwd Sequence test [%lu-%lu]. Wanted %lu. Got %lu\n",
                   start, stop, pid, node->data.pid);
            return 3;
        }
        node = list_prev(node);
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
        printf("Bwd Sequence test [%lu-%lu]. Wanted final %lu. Got %lu\n",
               start, stop, pid, node->data.pid);
        return 4;
    }
        
    return 0;
}

static int _compare_pid(list_data_t existing_elem, list_data_t new_elem)
{
    if (existing_elem.pid > new_elem.pid)
        return 1;
    
    if (existing_elem.pid < new_elem.pid)
        return -1;

    return 0;
    
}

void test_list()
{
    list_t p1;
    list_node_t* node;
    packet_id_t pid = 1;

    list_init(&p1);

    // 1
    list_push_tail(&p1, LIST_PID(1));
    if (_test_sequence(&p1, 1, 1)) {
        puts("Failed list test 1.1.\n");
        exit(0); 
    }
        
    // 2
    list_push_tail(&p1, LIST_PID(2));
    if (_test_sequence(&p1, 1, 2)) {
        puts("Failed list test 1.2.\n");
        exit(0); 
    }

    // 3
    list_push_tail(&p1, LIST_PID(3));
    if (_test_sequence(&p1, 1, 3)) {
        puts("Failed list test 1.3.\n");
        exit(0); 
    }

    // 4
    list_push_tail(&p1, LIST_PID(4));
    if (_test_sequence(&p1, 1, 4)) {
        puts("Failed list test 1.4.\n");
        exit(0); 
    }

    // 5
    list_push_tail(&p1, LIST_PID(5));
    if (_test_sequence(&p1, 1, 5)) {
        puts("Failed list test 1.5.\n");
        exit(0); 
    }

    // 6
    list_push_tail(&p1, LIST_PID(6));
    if (_test_sequence(&p1, 1, 6)) {
        puts("Failed list test 1.6.\n");
        exit(0); 
    }


    // Insert in middle of list.
    node = list_head(&p1);  // pid == 1
    node = list_next(node); // pid == 2
    node = list_next(node); // pid == 3
    list_insert_after(node, LIST_PID(31));

    // Validate list 
    if (node->data.pid != 3) {
        printf("Failed list test 2.1. Wanted 3 Got %lu\n",
               node->data.pid);
        exit(0); 
    }

    if (list_next(node)->data.pid != 31) {
        printf("Failed list test 2.2. Wanted 31 Got %lu\n",
               node->data.pid);
        exit(0); 
    }

    if (list_next(list_next(node))->data.pid != 4) {
        printf("Failed list test 2.3. Wanted 4 Got %lu\n",
               node->data.pid);
        exit(0); 
    }

    // Delete the element we just put in
    node = list_next(node);
    list_delete(node);

    if (_test_sequence(&p1, 1, 6)) {
        puts("Failed list test 3.1.\n");
        exit(0); 
    }
    
    // Delete tail element
    list_delete(list_tail(&p1));
    if (_test_sequence(&p1, 1, 5)) {
        puts("Failed list test 3.2.\n");
        exit(0); 
    }

    // Delete head element
    list_delete(list_head(&p1));
    if (_test_sequence(&p1, 2, 5)) {
        puts("Failed list test 3.3.\n");
        exit(0); 
    }

    //
    // Test sorted by pid
    //
    while(list_size(&p1))
        list_pop_head(&p1);


    list_insert_sorted(&p1, LIST_PID(2), _compare_pid);
    if (_test_sequence(&p1, 2, 2)) {
        puts("Failed list test 4.1.\n");
        exit(0); 
    }

    list_insert_sorted(&p1, LIST_PID(1), _compare_pid);
    if (_test_sequence(&p1, 2, 1)) {
        puts("Failed list test 4.2.\n");
        exit(0); 
    }

    list_insert_sorted(&p1, LIST_PID(3), _compare_pid);
    if (_test_sequence(&p1, 3, 1)) {
        puts("Failed list test 4.3.\n");
        exit(0); 
    }

    list_insert_sorted(&p1, LIST_PID(7), _compare_pid);
    list_insert_sorted(&p1, LIST_PID(6), _compare_pid);
    list_insert_sorted(&p1, LIST_PID(5), _compare_pid);

    list_insert_sorted(&p1, LIST_PID(4), _compare_pid);
    if (_test_sequence(&p1, 7, 1)) {
        puts("Failed list test 4.4.\n");
        exit(0); 
    }

    list_insert_sorted(&p1, LIST_PID(8), _compare_pid);
    if (_test_sequence(&p1, 8, 1)) {
        puts("Failed list test 4.5.\n");
        exit(0); 
    }

}


#endif // INCLUDE_TEST
