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
#include <errno.h>


void circ_buf_hex_dump(circ_buf_t* circ_buf)
{
    uint32_t ind = circ_buf->start_ind;
    uint32_t count = 0;

    printf("Circ dump\n");
    printf("size:        %d\n", circ_buf->size);
    printf("start_ind:   %d\n", circ_buf->start_ind);
    printf("stop_ind:    %d\n", circ_buf->stop_ind);
    printf("in_use:      %d\n", circ_buf_in_use(circ_buf));
    printf("available:   %d\n", circ_buf_available(circ_buf));
    printf("total:       %d\n", circ_buf_available(circ_buf) + circ_buf_in_use(circ_buf));

    while(ind != circ_buf->stop_ind)
    {
        printf("  Byte[%.5d] Ind[%d], Val[%.2X] [%.3d] ",
               count,
               ind, 
               circ_buf->buffer[ind] & 0xFF, 
               circ_buf->buffer[ind] & 0xFF);

        if (circ_buf->buffer[ind] > 31 && circ_buf->buffer[ind] < 127)
            printf("[%c]\n", circ_buf->buffer[ind]);
        else
            putchar('\n');

        count++;
        ind++;

        if (ind == circ_buf->size)
            ind = 0;
    }
    puts("---");
}

void check_integrity(circ_buf_t* cb,
                     int major_test,
                     uint32_t exp_available,
                     uint32_t exp_used)
{
    uint32_t ind = cb->start_ind;
    uint32_t count = 0;

    if (circ_buf_available(cb) != exp_available) {
        printf("circular buffer test %d.1: Wanted %d as available. Got %d\n",
               major_test, exp_available, circ_buf_available(cb));
        exit(255);
    }

    if (circ_buf_in_use(cb) != exp_used) {
        printf("circular buffer test %d.2: Wanted %d as in use. Got %d\n",
               major_test, exp_used, circ_buf_in_use(cb));
        exit(255);
    }

    // Go through and count the elements!


    while(ind != cb->stop_ind)
    {
        count++;
        ind++;
        if (ind == cb->size)
            ind = 0;
    }
    if (count != circ_buf_in_use(cb)) {
        printf("circular buffer test %d.2: In use shows %d elements, but I counted %dd\n",
               major_test, circ_buf_in_use(cb), count);
        exit(255);
    }
}

void read_data(circ_buf_t* cb,
               int major_test,
               uint8_t *expected_result)
{
    int bytes_to_read = strlen(expected_result);
    uint8_t* seg1 = 0;
    uint32_t seg1_len = 0;
    uint8_t* seg2 = 0;
    uint32_t seg2_len = 0;
    uint8_t data[bytes_to_read];
    uint32_t len = 0;
    uint32_t available = 0;
    uint32_t in_use = 0;
    int res = 0;
    uint32_t offset = 0;

    if (circ_buf_in_use(cb) < bytes_to_read) {
        printf("circular buffer test %d.1: Wanted %d bytes of data in use. Got %d\n",
               major_test, bytes_to_read, circ_buf_in_use(cb));

        exit(255);
    }
    
    available = circ_buf_available(cb);
    in_use = circ_buf_in_use(cb);

    res = circ_buf_read(cb, data, bytes_to_read, &len);
    if (res != 0) {
        printf("circular buffer test %d.2: Wanted return value 0 (OK). Got %s\n",
               major_test, strerror(res));

        exit(255);
    }

    if (len != bytes_to_read) {
        printf("circular buffer test %d.3: Wanted to read %d bytes. Got %d\n",
               major_test, bytes_to_read, res);

        exit(255);
    }

    if (memcmp(data, expected_result, bytes_to_read)) {
        uint32_t ind = 0;
        printf("circular buffer test %d.6: Data integrity failure.\n",
               major_test);

        printf("byte | expect | got\n");
               
        for(ind = 0; ind < bytes_to_read; ++ind) {
            if (expected_result[ind] == data[ind])
                printf(" %.3d      %c      %c\n",
                       ind,
                       (int) expected_result[ind],
                       (int) data[ind]);
            else
                printf("*%.3d      %c      %c\n",
                       
                       ind,
                       (int) expected_result[ind],
                       (int) data[ind]);
        }
        exit(255);
    }

    // Do an offset read from 0 to in_use to ensure that we have total
    // integrity across all offset cases for the given data.
    //
    
    while(offset != in_use) {
        uint8_t offset_data[in_use];
        memset(offset_data, 'X', in_use);
        
        
        res = circ_buf_read_offset(cb, offset, offset_data, bytes_to_read - offset, &len);
        if (res != 0) {
            printf("circular buffer test %d.7: Wanted return value 0 (OK). Got %s\n",
                   major_test, strerror(res));
            
            exit(255);
        }

        if (len != bytes_to_read - offset) {
            printf("circular buffer test %d.8: Wanted to read %d bytes. Got %d\n",
                   major_test, bytes_to_read - offset, res);

            exit(255);
        }
        
        if (memcmp(offset_data, expected_result + offset, bytes_to_read - offset)) {
            uint32_t ind = 0;
            
            printf("circular buffer test %d.6: Offset integrity failure. Offset[%d]\n", 
                   major_test, offset);

            printf("byte | expect | got\n");
               
            for(ind = 0; ind < bytes_to_read-offset; ++ind) {
                if (expected_result[ind+offset] == offset_data[ind])
                    printf(" %.3d      %c      %c\n",
                           ind,
                           (int) expected_result[ind+offset],
                           (int) offset_data[ind]);
                else
                    printf("*%.3d      %c      %c\n",
                       
                           ind,
                           (int) expected_result[ind+offset],
                           (int) offset_data[ind]);
            }
            exit(255);
        }
        ++offset;
    }

    circ_buf_free(cb, bytes_to_read, 0);
    if (circ_buf_available(cb) != available + bytes_to_read) {
        printf("circular buffer test %d.4: Expected post read available %d. Got %d\n",
               major_test, available + bytes_to_read, circ_buf_available(cb));

        exit(255);
    }

    if (circ_buf_in_use(cb) != in_use - bytes_to_read ) {
        printf("circular buffer test %d.5: Expected post read in_use %d. Got %d\n",
               major_test, in_use - bytes_to_read, circ_buf_in_use(cb));

        exit(255);
    }
    
}

void write_data(circ_buf_t* cb,
                int major_test,
                uint8_t* data,
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
    uint32_t data_len = strlen(data);
    
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
        memcpy(seg2, data+seg1_len, seg2_len);

    return;
}

void test_circular_buffer(void)
{
    circ_buf_t cb;
    uint8_t buf1[5];
    uint8_t data[5];
    int res = 0;
    uint8_t* seg1 = 0;
    uint32_t seg1_len = 0;
    uint8_t* seg2 = 0;
    uint32_t seg2_len = 0;
    uint32_t len = 0;
    uint8_t buf2[0xFFC4];
    circ_buf_init(&cb, buf1, sizeof(buf1));


    check_integrity(&cb, 1, sizeof(buf1)-1, 0);

    // Write and read a single byte 7 times for two-time wrap.
    write_data(&cb, 2, "1",  1, 0);
    check_integrity(&cb, 3, 3, 1);
    read_data(&cb, 3, "1");
    check_integrity(&cb, 3, 4, 0);

    write_data(&cb, 4, "2", 1, 0);
    check_integrity(&cb, 3, 3, 1);
    read_data(&cb, 5, "2");
    check_integrity(&cb, 3, 4, 0);

    write_data(&cb, 6, "3", 1, 0);
    check_integrity(&cb, 3, 3, 1);
    read_data(&cb, 7, "3");
    check_integrity(&cb, 3, 4, 0);

    write_data(&cb, 8, "4", 1, 0);
    check_integrity(&cb, 3, 3, 1);
    read_data(&cb, 9, "4");
    check_integrity(&cb, 3, 4, 0);

    write_data(&cb, 10, "5", 1, 0);
    check_integrity(&cb, 3, 3, 1);
    read_data(&cb, 11, "5");
    check_integrity(&cb, 3, 4, 0);

    write_data(&cb, 12, "6", 1, 0);
    check_integrity(&cb, 3, 3, 1);
    read_data(&cb, 13, "6");
    check_integrity(&cb, 3, 4, 0);

    write_data(&cb, 14, "7", 1, 0);
    check_integrity(&cb, 3, 3, 1);
    read_data(&cb, 15, "7");
    check_integrity(&cb, 3, 4, 0);

    write_data(&cb, 16, "8", 1, 0);
    check_integrity(&cb, 3, 3, 1);
    read_data(&cb, 17, "8");
    check_integrity(&cb, 3, 4, 0);

    write_data(&cb, 18, "9", 1, 0);
    check_integrity(&cb, 3, 3, 1);
    read_data(&cb, 19, "9");
    check_integrity(&cb, 3, 4, 0);

    write_data(&cb, 20, "A", 1, 0);
    check_integrity(&cb, 3, 3, 1);
    read_data(&cb, 21, "A");
    check_integrity(&cb, 3, 4, 0);

    write_data(&cb, 22, "B", 1, 0);
    check_integrity(&cb, 3, 3, 1);
    read_data(&cb, 23, "B");
    check_integrity(&cb, 3, 4, 0);

    // Reset by freeing more bytes than the size of the buffre.
    res = circ_buf_free(&cb, 6, &len);
    if (res != 0) {
        printf("circular buffer test 1.1: Expected OK. Got %s\n",
               strerror(res));
        exit(255);
    }

    if (len != 0) {
        printf("circular buffer test 1.1: Expected 0. Got %d\n", len);
        exit(255);
    }

    check_integrity(&cb, 3, 4, 0);

    // Test if we can do a wrapped write.

    // Write four bytes to fill up slot 0-3 in the buffer.
    //
    // S = start of data in use
    // s = First byte *after* last data byte in yse.
    // X = start and stop of data in use.
    //
    // After write:
    // Index:     [0][1][2][3][4]
    // Data:       A  B  C  D  -
    // Start/stop  S           s
    // Please note that the buffer is full since we have
    // one byte reserved to distinguish between empty
    // and full vuffer, in which both cases start and stop
    // would point to the same byte if we did not have 
    // the reserved byte.]
    write_data(&cb, 24, "ABCD", 4, 0);
    check_integrity(&cb, 26, 0, 4);

    // Read back three bytes to open up 0-2 in the circular buffer
    // We now have 4 bytes available at slots 4, 0, 1, 2
    // with the start index being at 3 and stop index at 4
    //
    // After read:
    // Index:     [0][1][2][3][4]
    // Data:       -  -  -  D  -
    // Start/stop           S  s
    read_data(&cb, 25, "ABC");
    check_integrity(&cb, 26, 3, 1);

    // Write 3 bytes of wrapping data in slote 4,0,1.
    // One bytes should be stored in segment one (slot 4)
    // and one two bytes should be stored in segment 2 (slot 0,1(
    //
    // After write:
    // Index:     [0][1][2][3][4]
    // Data:       B  C  -  D  A
    // Start/stop        s  S  
    write_data(&cb, 27, "ABC", 1, 2);
    check_integrity(&cb, 28, 0, 4);

    // Read out all four bytes in a wrapped
    // read that encompasses the last byte of the second-to-last
    // write, and all three bytes of last write.
    //
    // After read:
    // Index:     [0][1][2][3][4]
    // Data:       -  -  -  -  -
    // Start/stop        X  
    read_data(&cb, 29, "DABC");
    check_integrity(&cb, 30, 4, 0);
    
    //
    // Check alloc beyond our capacity.
    //
    res = circ_buf_alloc(&cb, 5, &seg1, &seg1_len, &seg2, &seg2_len);
    if (res != ENOMEM) {
        printf("circular buffer test 31.1: Expected ENOMEM. Got %s\n",
               strerror(res));
        exit(255);
    }
    // Reset by freeing more bytes than the size of the buffre.
    res = circ_buf_free(&cb, 6, &len);
    if (res != 0) {
        printf("circular buffer test 31.2: Expected OK. Got %s\n",
               strerror(res));
        exit(255);
    }

    if (len != 0) {
        printf("circular buffer test 31.3: Expected 0. Got %d\n", len);
        exit(255);
    }

    write_data(&cb, 24, "ABC", 3, 0);
    
    res = circ_buf_read(&cb, data, 100, &len);
    if (res != 0) {
        printf("circular buffer test 31.4 Expected OK. Got %s\n",
               strerror(res));
        exit(255);
    }

    if (len != 3) {
        printf("circular buffer test 31.5: Expected 3. Got %d\n", len);
        exit(255);
    }


    //
    // Test circ_buf_trim()
    //
    circ_buf_free(&cb, sizeof(buf1), 0);
    write_data(&cb, 32, "ABCD", 4, 0);
    circ_buf_trim(&cb, 2);
    check_integrity(&cb, 33, 2, 2);
    read_data(&cb, 34, "AB");
    check_integrity(&cb, 35, 4, 0);
    write_data(&cb, 36, "CD", 2, 1);
    read_data(&cb, 37, "CD");
    check_integrity(&cb, 38, 4, 0);

    // Bug found during higher-level testing
    circ_buf_init(&cb, buf2, sizeof(buf2));
    
    res = circ_buf_alloc(&cb, circ_buf_available(&cb), &seg1, &seg1_len, &seg2, &seg2_len);
    if (res) {
        printf("circular buffer test 32.1: Expected OK. Got %s\n", strerror(res));
        exit(255);
    }
    circ_buf_trim(&cb, 9);

    res = circ_buf_alloc(&cb, circ_buf_available(&cb), &seg1, &seg1_len, &seg2, &seg2_len);
    if (res) {
        printf("circular buffer test 32.2: Expected OK. Got %s\n", strerror(res));
        exit(255);
    }
    circ_buf_trim(&cb, 9);

    res = circ_buf_alloc(&cb, circ_buf_available(&cb), &seg1, &seg1_len, &seg2, &seg2_len);
    if (res) {
        printf("circular buffer test 32.3: Expected OK. Got %s\n", strerror(res));
        exit(255);
    }
    circ_buf_trim(&cb, 9);

    res = circ_buf_alloc(&cb, circ_buf_available(&cb), &seg1, &seg1_len, &seg2, &seg2_len);
    if (res) {
        printf("circular buffer test 32.4: Expected OK. Got %s\n", strerror(res));
        exit(255);
    }
    circ_buf_trim(&cb, 9);


    // Bug found during higher-level testing
    circ_buf_init(&cb, buf2, 65);

    // Setup start situation
    cb.start_ind = 8;
    cb.stop_ind = 7;

    // Copy in data that preluded the corruption.
    memcpy(cb.buffer + 8, "0x01\0x13\0x00\0x00\0x00\0x00\0x00\0x00\0x00\0x08\0x00\0x31\0x3A\0x31\0x39\0x3A\0x32\0x30\0x00\0x01\0x14\0x00\0x00\0x00\0x00\0x00\0x00\0x00\0x08\0x00\0x31\0x3A\0x32\0x30\0x3A\0x32\0x30\0x00", 38);
    // The trimming caused the bug, bringing in_use down to 26
    circ_buf_trim(&cb, 38);
    check_integrity(&cb, 32, 64-38, 38);
}
