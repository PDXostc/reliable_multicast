// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "circular_buffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>


void check_integrity(circ_buf_t* cb,
                     int major_test,
                     uint32_t exp_available,
                     uint32_t exp_used)
{
    if (circ_buf_available(cb) != exp_available) {
        printf("circular buffer test %d.1: Wanted %d Got %d\n",
               major_test, exp_available, circ_buf_available(cb));
        exit(255);
    }

    if (circ_buf_in_use(cb) != 0) {
        printf("circular buffer test %d.2: Wanted %d Got %d\n",
               major_test, exp_used, circ_buf_in_use(cb));
        exit(255);
    }
}

void read_data(circ_buf_t* cb,
               int major_test,
               uint8_t *expected_result,
               int bytes_to_read)
{
    uint8_t* seg1 = 0;
    uint32_t seg1_len = 0;
    uint8_t* seg2 = 0;
    uint32_t seg2_len = 0;
    uint8_t data[bytes_to_read];
    uint32_t res;
    uint32_t available = 0;
    uint32_t in_use = 0;
    
    if (circ_buf_in_use(cb) < bytes_to_read) {
        printf("circular buffer test %d.1: Wanted %d bytes of data in use. Got %d\n",
               major_test, bytes_to_read, circ_buf_in_use(cb));

        exit(255);
    }
    
    available = circ_buf_available(cb);
    in_use = circ_buf_in_use(cb);

    res = circ_buf_read(cb, data, bytes_to_read);
    if (res != bytes_to_read) {
        printf("circular buffer test %d.2: Wanted to read %d bytes. Got %d\n",
               major_test, bytes_to_read, res);

        exit(255);
    }

    if (circ_buf_available(cb) != available + bytes_to_read) {
        printf("circular buffer test %d.3: Expected post read available %d. Got %d\n",
               major_test, available + bytes_to_read, circ_buf_available(cb));

        exit(255);
    }

    if (circ_buf_in_use(cb) != in_use - bytes_to_read ) {
        printf("circular buffer test %d.4: Expected post read in_use %d. Got %d\n",
               major_test, in_use - bytes_to_read, circ_buf_in_use(cb));

        exit(255);
    }

    if (memcmp(data, expected_result, bytes_to_read)) {
        uint32_t ind = 0;
        printf("circular buffer test %d.5: Data integrity failure.\n",
               major_test);

        printf("byte|expect|got\n");
               
        for(ind = 0; ind < bytes_to_read; ++ind) {
            if (expected_result[ind] == data[ind])
                printf(" %.3d  %.2X    %.2X\n",
                       ind,
                       (int) expected_result[ind],
                       (int) data[ind]);
            else
                printf("*%.3d  %.2X    %.2X\n",
                       ind,
                       (int) expected_result[ind],
                       (int) data[ind]);
        }
        exit(255);
    }
}

void write_data(circ_buf_t* cb,
                int major_test,
                uint8_t* data,
                uint32_t data_len,
                uint32_t exp_seg1_len,
                uint32_t exp_seg2_len)
{
    int res; 
    uint8_t* seg1 = 0;
    uint32_t seg1_len = 0;
    uint8_t* seg2 = 0;
    uint32_t seg2_len = 0;
    uint32_t available = 0;
    uint32_t in_use = 0;
    
    if (circ_buf_available(cb) < data_len) {
        printf("circular buffer test %d.1: Wanted %d bytes of data available. Got %d\n",
               major_test, data_len, circ_buf_available(cb));

        exit(255);
    }
    
    
    available = circ_buf_available(cb);
    in_use = circ_buf_in_use(cb);
    res = circ_buf_alloc(cb, data_len, &seg1, &seg1_len, &seg2, &seg2_len);
    if (res != 0) {
        printf("circular buffer test %d.2: circ_buf_alloc(%d): %s\n",
               major_test, data_len, strerror(res));

        exit(255);
    }

    if (circ_buf_available(cb) != available - data_len) {
        printf("circular buffer test %d.3: Expected post alloc available %d. Got %d\n",
               major_test, available - data_len, circ_buf_available(cb));

        exit(255);
    }

    if (circ_buf_in_use(cb) != in_use + data_len ) {
        printf("circular buffer test %d.4: Expected post alloc in_use %d. Got %d\n",
               major_test, in_use + data_len, circ_buf_in_use(cb));

        exit(255);
    }

    if (seg1_len != exp_seg1_len) {
        printf("circular buffer test %d.5: Expected segment 1 len %d. Got %d\n",
               major_test, exp_seg1_len, seg1_len);

        exit(255);
    }

    if (seg1_len != exp_seg1_len) {
        printf("circular buffer test %d.6: Expected segment 2 len %d. Got %d\n",
               major_test, exp_seg2_len, seg2_len);

        exit(255);
    }
    memcpy(seg1, data, seg1_len);

    if (seg2_len) 
        memcpy(seg2, data, seg2_len);

    return;
}

void test_circular_buffer(void)
{
    circ_buf_t cb;
    uint8_t buf1[3];
    int res = 0;

    circ_buf_init(&cb, buf1, sizeof(buf1));

    check_integrity(&cb, 1, 3, 0);

    // Write and read a single byte 7 times for two-time wrap.
    write_data(&cb, 2, "1", 1, 1, 0);
    read_data(&cb, 3, "1", 1);

    write_data(&cb, 4, "2", 1, 1, 0);
    read_data(&cb, 5, "2", 1);

    write_data(&cb, 6, "3", 1, 1, 0);
    read_data(&cb, 7, "3", 1);

    write_data(&cb, 8, "4", 1, 1, 0);
    read_data(&cb, 9, "4", 1);

    write_data(&cb, 10, "5", 1, 1, 0);
    read_data(&cb, 11, "5", 1);

    write_data(&cb, 12, "6", 1, 1, 0);
    read_data(&cb, 13, "6", 1);

    write_data(&cb, 14, "7", 1, 1, 0);
    read_data(&cb, 15, "7", 1);

    write_data(&cb, 16, "8", 1, 1, 0);
    read_data(&cb, 17, "8", 1);

    write_data(&cb, 18, "9", 1, 1, 0);
    read_data(&cb, 19, "9", 1);

}



