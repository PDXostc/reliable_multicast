// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com);

#ifndef __CIRCULAR_BUFFER_H__
#define __CIRCULAR_BUFFER_H__

#include <stdint.h>
typedef struct circ_buf {
    // Total number of bytes pointed to by buffer.
    uint32_t size;

    // Index to first byte of used data in buffer
    uint32_t start_ind;

    // Index to last byte of used data in buffer. May be less than start_ind
    uint32_t stop_ind;

    // Circular buffer space provided by circ_buf_init()
    uint8_t *buffer;
} circ_buf_t;


extern void circ_buf_init(circ_buf_t* circ_buf, uint8_t* buffer, uint32_t buffer_size);
extern uint32_t circ_buf_available(circ_buf_t* circ_buf);
extern uint32_t circ_buf_in_use(circ_buf_t* circ_buf);

extern int circ_buf_alloc(circ_buf_t* circ_buf,
                          uint32_t len,
                          uint8_t **segment1,
                          uint32_t* segment1_len,
                          uint8_t **segment2,
                          uint32_t* segment2_len);

extern void circ_buf_trim(circ_buf_t* circ_buf, uint32_t target_len);

extern  int circ_buf_free(circ_buf_t* circ_buf,
                          uint32_t size,
                          uint32_t* in_use);

extern int circ_buf_read(circ_buf_t* circ_buf,
                         uint8_t* target,
                         uint32_t size,
                         uint32_t* bytes_read);

extern int circ_buf_read_segment(circ_buf_t* circ_buf,
                                 uint32_t size,
                                 uint8_t **segment1,
                                 uint32_t* segment1_len,
                                 uint8_t **segment2,
                                 uint32_t* segment2_len);

#endif // __CIRCULAR_BUFFER_H__
