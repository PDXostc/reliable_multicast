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


extern void circ_buf_init(circ_buf_t* circ_buf, uint8_t* buffer, uint32_t buffer_size)
{
    circ_buf->start_ind = 0;
    circ_buf->stop_ind = 0;
    circ_buf->buffer = buffer;
    circ_buf->size = buffer_size;
}

uint32_t circ_buf_in_use(circ_buf_t* circ_buf)
{
    int buf_size = circ_buf->size;

    if (circ_buf->stop_ind >= circ_buf->start_ind)
        return circ_buf->stop_ind - circ_buf->start_ind;

    return buf_size - circ_buf->start_ind + circ_buf->stop_ind;
}

uint32_t circ_buf_available(circ_buf_t* circ_buf)
{
    return circ_buf->size - circ_buf_in_use(circ_buf);
}

int circ_buf_alloc(circ_buf_t* circ_buf,
                   uint32_t len,
                   uint8_t **segment1,
                   uint32_t* segment1_len,
                   uint8_t **segment2,
                   uint32_t* segment2_len)
{
    uint32_t buf_size = circ_buf->size;
    uint32_t available_size = circ_buf_available(circ_buf);

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



// Return number of bytes left after discarding data.
inline uint32_t circ_buf_free(circ_buf_t* circ_buf, uint32_t size)
{
    uint32_t len = circ_buf_in_use(circ_buf);

    // Can we do a quickie?
    if (size >= len) {
        circ_buf->start_ind = 0;
        circ_buf->stop_ind = 0;
        return 0;
    }

    circ_buf->start_ind += size;
    circ_buf->start_ind %= circ_buf->size;

    return len - size;
}


inline uint32_t circ_buf_read(circ_buf_t* circ_buf,
                              uint8_t* target,
                              uint32_t size)
{
    uint32_t len = circ_buf_in_use(circ_buf);
    uint32_t segment_len = 0;
    uint32_t copied_bytes = 0;
    
    len = RMC_MIN(len, size);

    // If the entire data of buffer is stored without
    // wrapping the buffer we can just copy it in one operation
    // and be done.
    if (circ_buf->stop_ind >= circ_buf->start_ind) {
        memcpy(target, circ_buf->buffer + circ_buf->start_ind, len);
        return len;
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
    if (len <= segment_len) 
        return copied_bytes;
    
    // Copy out the secont part of the circular buffer, spanning from
    // 0 to either stop_ind (last data byte) or the number of bytes left
    // wanted by the caller, whichever is smaller.
    len -= segment_len;
    segment_len = RMC_MIN(len, circ_buf->stop_ind);
    memcpy(target + segment_len, circ_buf->buffer, segment_len);

    copied_bytes += segment_len;

    return copied_bytes;
}
