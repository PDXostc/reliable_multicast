// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)


#ifndef __RMC_LIST_H__
#define __RMC_LIST_H__

#include <stdint.h>


#define RMC_LIST(LISTTYPE, NODETYPE, DATATYPE)            \
    typedef struct _##LISTTYPE {                          \
        struct _##NODETYPE * head;                        \
        struct _##NODETYPE * tail;                        \
        uint32_t elem_count;                              \
        void* user_data;                                            \
        struct _##LISTTYPE (*alloc_list)(void* user_data);          \
        struct _##LISTTYPE (*free_list)(void* user_data);           \
        struct _##NODETYPE * (*alloc_node)(void* user_data);        \
        void (*free_node)(struct _##NODETYPE * node, void* user_data);  \
    } LISTTYPE;                                                     \
                                                          \
    typedef struct _##NODETYPE {                          \
        DATATYPE data;                                    \
        struct _##NODETYPE * next;                        \
        struct _##NODETYPE * prev;                        \
        LISTTYPE* owner;                                  \
    } NODETYPE;                                           \
                                                          \
    extern void LISTTYPE##_init(LISTTYPE* list,                         \
                                void* user_data,                        \
                                NODETYPE* (*alloc_node)(void* user_data), \
                                void (*free_node)(NODETYPE* node, void* user_data) \
        );                                                              \
                                                                        \
    extern uint32_t LISTTYPE##_size(LISTTYPE* list);                    \
                                                                        \
    extern NODETYPE* LISTTYPE##_head(LISTTYPE* list);                     \
    extern NODETYPE* LISTTYPE##_tail(LISTTYPE* list);                   \
                                                                        \
                                                                        \
    extern NODETYPE* LISTTYPE##_prev(NODETYPE* node);                   \
    extern NODETYPE* LISTTYPE##_next(NODETYPE* node);                   \
                                                                        \
    extern NODETYPE* LISTTYPE##_push_head(LISTTYPE* list, DATATYPE data); \
    extern NODETYPE* LISTTYPE##_push_head_node(LISTTYPE* list, NODETYPE* node) ; \
                                                                        \
    extern NODETYPE* LISTTYPE##_push_tail(LISTTYPE* list, DATATYPE data); \
    extern NODETYPE* LISTTYPE##_push_tail_node(LISTTYPE* list, NODETYPE* node) ; \
                                                                        \
    extern NODETYPE* LISTTYPE##_insert_before_node(NODETYPE* prev, NODETYPE* data); \
    extern NODETYPE* LISTTYPE##_insert_before(NODETYPE* prev, DATATYPE data); \
                                                                        \
    extern NODETYPE* LISTTYPE##_insert_after_node(NODETYPE* prev, NODETYPE* data); \
    extern NODETYPE* LISTTYPE##_insert_after(NODETYPE* prev, DATATYPE data); \
                                                                        \
    extern NODETYPE* LISTTYPE##_unlink(NODETYPE* node);                 \
    extern void LISTTYPE##_delete(NODETYPE* node);                      \
                                                                        \
    extern int LISTTYPE##_pop_head(LISTTYPE* list, DATATYPE* data);     \
    extern NODETYPE* LISTTYPE##_pop_head_node(LISTTYPE* list);          \
    extern int LISTTYPE##_pop_tail(LISTTYPE* list, DATATYPE* data);     \
    extern NODETYPE* LISTTYPE##_pop_tail_node(LISTTYPE* list);          \
                                                                        \
    extern void LISTTYPE##_for_each(LISTTYPE* list,                     \
                                    uint8_t (*func)(NODETYPE*node, void* user_data), \
                                    void*user_data);                    \
                                                                        \
    extern NODETYPE* LISTTYPE##_find_node(LISTTYPE* list,               \
                                          DATATYPE data,                \
                                          int (*compare_func)(DATATYPE new_elem, \
                                                              DATATYPE existing_elem)); \
                                                                        \
                                                                        \
    extern NODETYPE* LISTTYPE##_insert_sorted(LISTTYPE* list,           \
                                              DATATYPE new_elem,        \
                                              int (*compare_func)(DATATYPE new_elem, \
                                                                  DATATYPE existing_elem)); \
                                                                        \
    extern NODETYPE* LISTTYPE##_insert_sorted_rev(LISTTYPE* list,       \
                                                  DATATYPE new_elem,    \
                                                  int (*compare_func)(DATATYPE new_elem, \
                                                                  DATATYPE existing_elem)); \
                                                                        \
    extern NODETYPE* LISTTYPE##_insert_sorted_node(LISTTYPE* list,      \
                                                   NODETYPE* node,      \
                                                   int (*compare_func)(DATATYPE new_elem, \
                                                                       DATATYPE existing_elem)); \
    extern NODETYPE* LISTTYPE##_insert_sorted_node_rev(LISTTYPE* list,  \
                                                       NODETYPE* node,  \
                                                       int (*compare_func)(DATATYPE new_elem, \
                                                                           DATATYPE existing_elem)); \

#endif // __RMC_LIST_H__


