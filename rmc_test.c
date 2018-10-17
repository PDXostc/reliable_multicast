// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "rmc_common.h"

extern void test_packet_interval();
extern void test_packet_intervals();
extern void run_list_tests();
extern void test_pub(void);
extern void test_sub(void);
extern void test_rmc_proto(void);




int main(int argc, char* argv[])
{
    run_list_tests();
    test_packet_interval();
    test_packet_intervals();
    test_pub();
    test_sub();
    test_rmc_proto();
}
