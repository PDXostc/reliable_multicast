// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "rmc_common.h"
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void test_packet_interval();
extern void test_packet_intervals();
extern void run_list_tests();
extern void test_pub(void);
extern void test_sub(void);
extern void test_rmc_proto_pub(char* mcast_addr,
                               char* mcast_if_addr,
                               char* listen_if_addr,
                               int mcast_port,
                               int listen_port);

extern void test_rmc_proto_sub(char* mcast_addr,
                               char* mcast_if_addr,
                               char* listen_if_addr,
                               int mcast_port,
                               int listen_port);

extern void test_circular_buffer(void);

#define LISTEN_IF_ADDR_DEFAULT "0.0.0.0"
#define MULTICAST_IF_ADDR_DEFAULT "0.0.0.0"
#define MULTICAST_ADDR_DEFAULT "239.0.0.1"
#define PORT_DEFAULT 4723

void usage(char* prog)
{
    fprintf(stderr,
            "Usage: %s [-P] [-M <ip-addr>] [-m <ip-addr>] [-l <ip-addr>] [-P <port>] [-p <port>]\n",
            prog);
    fprintf(stderr, "       -S             Run as subscriber instead of default publisher\n");
    fprintf(stderr, "       -M <ip-addr>   Multicast IP address (default: %s)\n", MULTICAST_ADDR_DEFAULT);
    fprintf(stderr, "       -m <ip-addr>   Multicast interface IP (default: %s)\n", MULTICAST_IF_ADDR_DEFAULT);
    fprintf(stderr, "       -l <ip-addr>   Listen interface IP (default: %s)\n", LISTEN_IF_ADDR_DEFAULT);
    fprintf(stderr, "       -P <port>      Multicast port (default: %d)\n", PORT_DEFAULT);
    fprintf(stderr, "       -p <port>      Listen  port (default: %d)\n", PORT_DEFAULT);
}

int main(int argc, char* argv[])
{
    int tst = 1;
    int opt = 0;
    int publisher = 1;
    char mcast_group_addr[80] = { 0 };
    char mcast_if_addr[80] = { 0 };
    char listen_if_addr[80];
    int listen_port = PORT_DEFAULT;
    int mcast_port = PORT_DEFAULT;

    strcpy(mcast_if_addr, MULTICAST_IF_ADDR_DEFAULT);
    strcpy(listen_if_addr, LISTEN_IF_ADDR_DEFAULT);
    strcpy(mcast_group_addr, MULTICAST_ADDR_DEFAULT);
    
    while ((opt = getopt(argc, argv, "SP:M:m:l:p:")) != -1) {
        switch (opt) {

        case 'S':
            publisher = 0;
            break;
            
        case 'M':
            strcpy(mcast_group_addr, optarg);
            break;

        case 'm':
            strcpy(mcast_if_addr, optarg);
            break;

        case 'l':
            strcpy(listen_if_addr, optarg);
            break;

        case 'P':
            mcast_port = atoi(optarg);
            break;

        case 'p':
            listen_port = atoi(optarg);
            break;

        default: /* '?' */
            usage(argv[0]);
            exit(1);
        }
    }
    
    run_list_tests();
    test_packet_interval();
    test_packet_intervals();
    test_circular_buffer();
    test_pub();
    test_sub();

    // Check with mode we run in.
    if (publisher)
        test_rmc_proto_pub(mcast_group_addr, mcast_if_addr, listen_if_addr, mcast_port, listen_port);
    else
        test_rmc_proto_sub(mcast_group_addr, mcast_if_addr, listen_if_addr, mcast_port, listen_port + 1);
        
    exit(0);
}
