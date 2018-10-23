// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)
// Trivial double linked list.

#include <assert.h>

#define RMC_LIST_IMPL(LISTTYPE, NODETYPE, DATATYPE)                     \
    static inline NODETYPE* NODETYPE##_rmc_alloc_node(void* user_data)  \
    {                                                                   \
        NODETYPE* res = (NODETYPE*) malloc(sizeof(NODETYPE));           \
        assert(res);                                                    \
        return res;                                                     \
    }                                                                   \
                                                                        \
    static inline void NODETYPE##_rmc_free_node(NODETYPE* node, void* user_data) \
    {                                                                   \
        assert(node);                                                   \
        free((void*) node);                                             \
    }                                                                   \
                                                                        \
    void LISTTYPE##_init(LISTTYPE* list,                                \
                         void* user_data,                               \
                         NODETYPE* (*alloc_node)(void* user_data),      \
                         void (*free_node)(NODETYPE* node, void* user_data)) \
    {                                                                   \
        list->head = 0;                                                 \
        list->tail = 0;                                                 \
        list->elem_count = 0;                                           \
        list->user_data = user_data;                                    \
        list->alloc_node = alloc_node?alloc_node:NODETYPE##_rmc_alloc_node; \
        list->free_node = free_node?free_node:NODETYPE##_rmc_free_node; \
    }                                                                   \
                                                                        \
    inline NODETYPE* LISTTYPE##_head(LISTTYPE* list)                    \
    {                                                                   \
        assert(list);                                                   \
                                                                        \
        return list->head;                                              \
    }                                                                   \
                                                                        \
    inline NODETYPE* LISTTYPE##_tail(LISTTYPE* list)                    \
    {                                                                   \
        assert(list);                                                   \
                                                                        \
        return list->tail;                                              \
    }                                                                   \
                                                                        \
    inline NODETYPE* LISTTYPE##_prev(NODETYPE* node)                    \
    {                                                                   \
        if (node)                                                       \
            return node->prev;                                          \
                                                                        \
        return 0;                                                       \
    }                                                                   \
                                                                        \
    inline NODETYPE* LISTTYPE##_next(NODETYPE* node)                    \
    {                                                                   \
        if (node)                                                       \
            return node->next;                                          \
                                                                        \
        return 0;                                                       \
    }                                                                   \
                                                                        \
                                                                        \
    inline uint32_t LISTTYPE##_size(LISTTYPE* list)                     \
    {                                                                   \
        assert(list);                                                   \
                                                                        \
        return list->elem_count;                                        \
    }                                                                   \
                                                                        \
                                                                        \
    inline NODETYPE* LISTTYPE##_push_head_node(LISTTYPE* owner, NODETYPE* node) \
    {                                                                   \
        assert(owner);                                                  \
        assert(node);                                                   \
                                                                        \
        node->next = owner->head;                                       \
        node->prev = 0;                                                 \
        node->owner = owner;                                            \
                                                                        \
        if (owner->head)                                                \
            owner->head->prev = node;                                   \
                                                                        \
        owner->head = node;                                             \
                                                                        \
        if (owner->tail == 0)                                           \
            owner->tail = node;                                         \
                                                                        \
        owner->elem_count++;                                            \
        return node;                                                    \
    }                                                                   \
                                                                        \
    NODETYPE* LISTTYPE##_push_head(LISTTYPE* list, DATATYPE data)       \
    {                                                                   \
        NODETYPE* node = (*list->alloc_node)(list->user_data);          \
                                                                        \
        assert(node);                                                   \
        node->data = data;                                              \
        return LISTTYPE##_push_head_node(list, node);                   \
    }                                                                   \
                                                                        \
    inline NODETYPE* LISTTYPE##_push_tail_node(LISTTYPE* owner, NODETYPE* node) \
    {                                                                   \
        NODETYPE* tail = 0;                                             \
                                                                        \
        assert(owner);                                                  \
        if (!node)                                                      \
            assert(node);                                               \
                                                                        \
        node->next = 0;                                                 \
        node->prev = owner->tail;                                       \
        node->owner = owner;                                            \
                                                                        \
        if (owner->tail != 0)                                           \
            owner->tail->next = node;                                   \
                                                                        \
                                                                        \
        owner->tail = node;                                             \
                                                                        \
        if (owner->head == 0)                                           \
            owner->head = node;                                         \
                                                                        \
        owner->elem_count++;                                            \
        return node;                                                    \
    }                                                                   \
                                                                        \
    NODETYPE* LISTTYPE##_push_tail(LISTTYPE* list, DATATYPE data)       \
    {                                                                   \
        NODETYPE* node = (*list->alloc_node)(list->user_data);          \
                                                                        \
        assert(node);                                                   \
        node->data = data;                                              \
        return LISTTYPE##_push_tail_node(list, node);                   \
    }                                                                   \
                                                                        \
    inline NODETYPE* LISTTYPE##_insert_before_node(NODETYPE* next, NODETYPE* node) \
    {                                                                   \
        assert(node);                                                   \
        assert(next != 0);                                              \
        assert(next->owner !=0);                                        \
                                                                        \
        if (next == LISTTYPE##_head(next->owner))                       \
            return LISTTYPE##_push_head_node(next->owner, node);        \
                                                                        \
                                                                        \
        node->owner = next->owner;                                      \
        node->prev = next->prev;                                        \
                                                                        \
        node->prev->next = node;                                        \
                                                                        \
        next->prev = node;                                              \
        node->next = next;                                              \
                                                                        \
        node->owner->elem_count++;                                      \
        return node;                                                    \
    }                                                                   \
                                                                        \
    NODETYPE* LISTTYPE##_insert_before(NODETYPE* next, DATATYPE data)   \
    {                                                                   \
        NODETYPE* node = (*next->owner->alloc_node)(next->owner->user_data); \
        assert(node);                                                   \
        node->data = data;                                              \
        return LISTTYPE##_insert_before_node(next, node);               \
    }                                                                   \
                                                                        \
    inline NODETYPE* LISTTYPE##_insert_after_node(NODETYPE* prev, NODETYPE* node) \
    {                                                                   \
        assert(prev != 0);                                              \
        assert(prev->owner != 0);                                       \
                                                                        \
        if (prev == LISTTYPE##_tail(prev->owner))                       \
            return LISTTYPE##_push_tail_node(prev->owner, node);        \
                                                                        \
        node->owner = prev->owner;                                      \
        node->next = prev->next;                                        \
                                                                        \
        node->next->prev = node;                                        \
                                                                        \
        prev->next = node;                                              \
        node->prev = prev;                                              \
                                                                        \
        node->owner->elem_count++;                                      \
        return node;                                                    \
    }                                                                   \
                                                                        \
    NODETYPE* LISTTYPE##_insert_after(NODETYPE* next, DATATYPE data)    \
    {                                                                   \
        NODETYPE* node = (*next->owner->alloc_node)(next->owner->user_data); \
        assert(node);                                                   \
        node->data = data;                                              \
        return LISTTYPE##_insert_after_node(next, node);                \
    }                                                                   \
                                                                        \
                                                                        \
    inline NODETYPE* LISTTYPE##_unlink(NODETYPE* node)                         \
    {                                                                   \
        assert(node);                                                   \
        assert(node->owner);                                            \
                                                                        \
        if (node->prev)                                                 \
            node->prev->next = node->next;                              \
                                                                        \
        if (node->next)                                                 \
            node->next->prev = node->prev;                              \
                                                                        \
        if (node->owner->head == node)                                  \
            node->owner->head = node->next;                             \
                                                                        \
        if (node->owner->tail == node)                                  \
            node->owner->tail = node->prev;                             \
                                                                        \
        node->owner->elem_count--;                                      \
        return node;                                                    \
    }                                                                   \
                                                                        \
                                                                        \
    void LISTTYPE##_delete(NODETYPE* node)                              \
    {                                                                   \
        LISTTYPE##_unlink(node);                                        \
        (*node->owner->free_node)(node, node->owner->user_data);        \
    }                                                                   \
                                                                        \
                                                                        \
    inline NODETYPE* LISTTYPE##_pop_head_node(LISTTYPE* list)           \
    {                                                                   \
        assert(list);                                                   \
                                                                        \
        if (!list->head)                                                \
            return 0;                                                   \
                                                                        \
        return LISTTYPE##_unlink(list->head);                           \
    }                                                                   \
                                                                        \
    inline int LISTTYPE##_pop_head(LISTTYPE* list, DATATYPE* data)      \
    {                                                                   \
        assert(list);                                                   \
                                                                        \
        if (!list->head)                                                \
            return 0;                                                   \
                                                                        \
        *data = list->head->data;                                       \
                                                                        \
        LISTTYPE##_delete(list->head);                                  \
        return 1;                                                       \
    }                                                                   \
                                                                        \
                                                                        \
    inline int LISTTYPE##_pop_tail(LISTTYPE* list, DATATYPE* data)      \
    {                                                                   \
        assert(list);                                                   \
                                                                        \
        if (!list->tail)                                                \
            return 0;                                                   \
                                                                        \
        *data = list->tail->data;                                       \
                                                                        \
        LISTTYPE##_delete(list->tail);                                  \
        return 1;                                                       \
    }                                                                   \
                                                                        \
    inline NODETYPE* LISTTYPE##_pop_tail_node(LISTTYPE* list)           \
    {                                                                   \
        assert(list);                                                   \
                                                                        \
        if (!list->tail)                                                \
            return 0;                                                   \
                                                                        \
                                                                        \
        return LISTTYPE##_unlink(list->tail);                           \
    }                                                                   \
                                                                        \
                                                                        \
    void LISTTYPE##_for_each(LISTTYPE* list,                            \
                             uint8_t (*func)(NODETYPE* node, void* user_data), \
                             void* user_data)                           \
    {                                                                   \
        NODETYPE* node = 0;                                             \
        assert(list);                                                   \
                                                                        \
        node = list->head;                                              \
        while(node && (*func)(node, user_data))                         \
            node = node->next;                                          \
    }                                                                   \
                                                                        \
                                                                        \
    NODETYPE* LISTTYPE##_find_node(LISTTYPE* list,                      \
                                   DATATYPE data,                       \
                                   int (*compare_func)(DATATYPE new_elem, \
                                                       DATATYPE existing_elem)) \
    {                                                                   \
        NODETYPE* node = 0;                                             \
                                                                        \
        assert(list);                                                   \
        node = LISTTYPE##_head(list);                                   \
                                                                        \
        while(node) {                                                   \
            if ((*compare_func)(data, node->data) != 0)                            \
                return node;                                            \
                                                                        \
            node = node->next;                                          \
        }                                                               \
        return (NODETYPE*) 0;                                           \
    }                                                                   \
                                                                        \
                                                                        \
    NODETYPE* LISTTYPE##_insert_sorted_node(LISTTYPE* list,             \
                                            NODETYPE* new_node,         \
                                            int (*compare_func)(DATATYPE new_elem, \
                                                                DATATYPE existing_elem)) \
    {                                                                   \
        NODETYPE* node = 0;                                             \
                                                                        \
        assert(list);                                                   \
        node = LISTTYPE##_head(list);                                   \
                                                                        \
        while(node) {                                                   \
            if ((*compare_func)(new_node->data, node->data) >= 0) {     \
                return LISTTYPE##_insert_before_node(node, new_node);   \
            }                                                           \
            node = LISTTYPE##_next(node);                               \
        }                                                               \
                                                                        \
        return LISTTYPE##_push_tail_node(list, new_node);               \
    }                                                                   \
                                                                        \
    NODETYPE* LISTTYPE##_insert_sorted_node_rev(LISTTYPE* list,         \
                                                NODETYPE* new_node,     \
                                                int (*compare_func)(DATATYPE new_elem, \
                                                                    DATATYPE existing_elem)) \
    {                                                                   \
        NODETYPE* node = 0;                                             \
                                                                        \
        assert(list);                                                   \
        node = LISTTYPE##_tail(list);                                   \
                                                                        \
        while(node) {                                                   \
            if ((*compare_func)(new_node->data, node->data) >= 0) {     \
                return LISTTYPE##_insert_after_node(node, new_node);   \
            }                                                           \
            node = LISTTYPE##_prev(node);                               \
        }                                                               \
                                                                        \
        return LISTTYPE##_push_head_node(list, new_node);               \
    }                                                                   \
                                                                        \
                                                                        \
    NODETYPE* LISTTYPE##_insert_sorted(LISTTYPE* list,                  \
                                       DATATYPE new_elem,               \
                                       int (*compare_func)(DATATYPE new_elem, \
                                                           DATATYPE existing_elem)) \
    {                                                                   \
        NODETYPE* node = 0;                                             \
        NODETYPE* new_node = 0;                                         \
                                                                        \
        assert(list);                                                   \
                                                                        \
        new_node = (*list->alloc_node)(list->user_data);                \
        assert(new_node);                                               \
                                                                        \
        new_node->data = new_elem;                                      \
        return LISTTYPE##_insert_sorted_node(list, new_node, compare_func); \
    }                                                                   \
                                                                        \
    NODETYPE* LISTTYPE##_insert_sorted_rev(LISTTYPE* list,              \
                                           DATATYPE new_elem,           \
                                           int (*compare_func)(DATATYPE new_elem, \
                                                               DATATYPE existing_elem)) \
    {                                                                   \
        NODETYPE* node = 0;                                             \
        NODETYPE* new_node = 0;                                         \
        assert(list);                                                   \
                                                                        \
        new_node = (*list->alloc_node)(list->user_data);                \
        assert(new_node);                                               \
                                                                        \
        new_node->data = new_elem;                                      \
        return LISTTYPE##_insert_sorted_node_rev(list, new_node, compare_func); \
    }                                                                   \

