// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)



#include "circular_buffer.h"
#include <errno.h>
#include <memory.h>

#define RMC_MAX(x,y) ((x)>(y)?(x):(y))
#define RMC_MIN(x,y) ((x)<(y)?(x):(y))

// circ_buf_t::start_ind = First byte of data in use.
// circ_buf_t::stop_ind = First byte *AFTER* last data byte in use
//
// if circ_buf_t::start_ind == circ_buf_t::stop_ind then no data is stored.
//
// The last available byte in the buffer is resreved so that we can
// distinguish between empty and full buffer, which in both cases
// have start_ind and stop_ind point at the same index.
//
void circ_buf_init(circ_buf_t* circ_buf, uint8_t* buffer, uint32_t buffer_size)
{
    circ_buf->start_ind = 0;
    circ_buf->stop_ind = 0;
    circ_buf->buffer = buffer;
    circ_buf->size = buffer_size;
}

inline uint32_t circ_buf_in_use(circ_buf_t* circ_buf)
{
    int buf_size = circ_buf->size;

    if (circ_buf->stop_ind >= circ_buf->start_ind)
        return circ_buf->stop_ind - circ_buf->start_ind;

    return buf_size - circ_buf->start_ind + circ_buf->stop_ind;
}

inline uint32_t circ_buf_available(circ_buf_t* circ_buf)
{
    // Keep one byte reserved to distinguish between full and empty buffer.
    return circ_buf->size - circ_buf_in_use(circ_buf) - 1;
}

int circ_buf_alloc(circ_buf_t* circ_buf,
                   uint32_t len,
                   uint8_t **segment1,
                   uint32_t* segment1_len,
                   uint8_t **segment2,
                   uint32_t* segment2_len)
{
    uint32_t buf_size = 0;
    uint32_t available_size = 0;

    if (!circ_buf ||
        !segment1 || !segment1_len ||
        !segment2 || !segment2_len)
        return EINVAL;

    buf_size = circ_buf->size;
    available_size = circ_buf_available(circ_buf);

    // Do we have enough memory?
    if (available_size < len)
        return ENOMEM;

    // Can we fit the requested number of bytes into a single segmetn?
    if (buf_size - circ_buf->stop_ind >= len) {
        *segment1 = &circ_buf->buffer[circ_buf->stop_ind];
        *segment1_len = len;
        *segment2 = 0;
        *segment2_len = 0;
        circ_buf->stop_ind += len;
        return 0;
    }

    // We need two segments. Setup the first one.
    *segment1 = &circ_buf->buffer[circ_buf->stop_ind];
    *segment1_len = buf_size - circ_buf->stop_ind;
    len -= *segment1_len;

    // Setup second segment
    *segment2 = circ_buf->buffer;
    *segment2_len = len;

    // Update (wrapped) stop.
    circ_buf->stop_ind = len;

    return 0;
}

// Trim the end of the in use part of the buffer
// so that the new total length is target_len.
// All trimmed byte will be available for future
// circ_buf_alloc() calls.
//
void circ_buf_trim(circ_buf_t* circ_buf, uint32_t target_len)
{
    uint32_t in_use = circ_buf_in_use(circ_buf);

    if (in_use <= target_len)
        return;

    // target_len: 1
    // Before
    // Index:     [0][1][2][3][4]
    // Data:       A  B  C  D  -
    // Start/Stop  S           s
    //
    // After
    // Index:     [0][1][2][3][4]
    // Data:       A  B  -  -  -
    // Start/Stop  S  s         
    //
    if (circ_buf->stop_ind > target_len) {
        circ_buf->stop_ind -= in_use - target_len;
        return;
    }

    
    // target_len: 1
    // Before
    // Index:     [0][1][2][3][4]
    // Data:       C  D  -  A  B
    // Start/Stop        s  S  
    //
    // After
    // Index:     [0][1][2][3][4]
    // Data:       -  -  -  A  -
    // Start/Stop           S  s         
    //

    target_len -= circ_buf->stop_ind;

    circ_buf->stop_ind = circ_buf->size - target_len;
    
    return;
}


// Return number of bytes left in use after discarding data.
int circ_buf_free(circ_buf_t* circ_buf, uint32_t size, uint32_t* in_use)
{
    uint32_t len = 0;

    if (!circ_buf)
        return 0;

    if (!size)  {
        if (in_use)
            *in_use = circ_buf_in_use(circ_buf);
        return 0;
    }

    len = circ_buf_in_use(circ_buf);

    // Can we do a quickie?
    // If we can reset the buffer we have a greater chance
    // of circ_buf_alloc and circ_buf read being able to
    // to fit the entire operation into one continuous
    // segment of the buffer, this avoiding having to
    // do split segments.
    if (size >= len) {
        circ_buf->start_ind = 0;
        circ_buf->stop_ind = 0;
        if (in_use)
            *in_use = 0;

        return 0;
    }

    circ_buf->start_ind += size;
    circ_buf->start_ind %= circ_buf->size;

    if (in_use)
        *in_use = len-size;

    return 0;
}


int circ_buf_read(circ_buf_t* circ_buf,
                  uint8_t* target,
                  uint32_t size,
                  uint32_t* bytes_read)
{
    uint32_t len = circ_buf_in_use(circ_buf);
    uint32_t segment_len = 0;
    uint32_t copied_bytes = 0;

    if (!size || !circ_buf || !target)
        return EINVAL;

    len = RMC_MIN(len, size);

    // If the entire data of buffer is stored without
    // wrapping the buffer we can just copy it in one operation
    // and be done.
    if (circ_buf->stop_ind >= circ_buf->start_ind) {
        memcpy(target, circ_buf->buffer + circ_buf->start_ind, len);

        if (bytes_read)
            *bytes_read = len;

        return 0;
    }

    // Copy out the first part of the circular buffer, spanning from
    // start_ind (first data byte) to end either of buffer or the
    // length that we want, whichwever is smaller.

    segment_len = circ_buf->size - circ_buf->start_ind;
    segment_len = RMC_MIN(segment_len, len);

    memcpy(target, circ_buf->buffer + circ_buf->start_ind, segment_len);
    copied_bytes += segment_len;

    // Return if the copied data was all that was requested by the
    // caller.
    if (len <= segment_len) {
        if (bytes_read)
            *bytes_read = copied_bytes;

        return 0;
    }

    // Copy out the secont part of the circular buffer, spanning from
    // 0 to either stop_ind (last data byte) or the number of bytes left
    // wanted by the caller, whichever is smaller.
    len -= segment_len;
    segment_len = RMC_MIN(len, circ_buf->stop_ind);
    memcpy(target + segment_len, circ_buf->buffer, segment_len);

    copied_bytes += segment_len;

    if (bytes_read)
        *bytes_read = copied_bytes;

    return 0;
}

// FIXME: Add test in circular_buffer_test.c
int circ_buf_read_segment(circ_buf_t* circ_buf,
                          uint32_t size,
                          uint8_t **segment1,
                          uint32_t* segment1_len,
                          uint8_t **segment2,
                          uint32_t* segment2_len)
{
    uint32_t len = circ_buf_in_use(circ_buf);
    uint32_t segment_len = 0;
    uint32_t copied_bytes = 0;

    if (!circ_buf ||
        !segment1 || !segment1_len ||
        !segment2 || !segment2_len)
        return EINVAL;

    // No data?
    if (circ_buf->stop_ind == circ_buf->start_ind) {
        *segment1 = 0;
        *segment1_len = 0;
        *segment2 = 0;
        *segment2_len = 0;
        return 0;
    }

    len = RMC_MIN(len, size);

    *segment1 = circ_buf->buffer + circ_buf->start_ind;
    *segment1_len = RMC_MIN(len, circ_buf->size - circ_buf->start_ind);

    // Do we even need to set segment2?
    if (len <= circ_buf->size - circ_buf->start_ind) {
        *segment2 = 0;
        *segment2_len = 0;
        return 0;
    }

    len -= circ_buf->size - circ_buf->start_ind;

    *segment2 = circ_buf->buffer;
    *segment2_len = len;

    return 0;
}
