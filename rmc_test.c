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
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include "reliable_multicast.h"

extern void test_packet_interval();
extern void run_list_tests();
extern void test_pub(void);
extern void test_sub(void);
extern void test_rmc_proto_pub(char* mcast_group_addr,
                               char* mcast_if_addr,
                               char* listen_if_addr,
                               int mcast_port,
                               int listen_port,
                               rmc_context_id_t ctx_id,
                               uint64_t count,
                               int expected_subscribers,
                               int seed,
                               usec_timestamp_t send_interval, //usec
                               int jitter, // usec
                               float drop_rate);

extern void test_rmc_proto_sub(char* mcast_addr,
                               char* mcast_if_addr,
                               int mcast_port,
                               rmc_context_id_t ctx_id,
                               uint8_t* ctx_id_map,
                               int ctx_id_map_size);

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
    fprintf(stderr, "       -p <port>      Listen  port (default: %d)\n\n", PORT_DEFAULT);
    
    fprintf(stderr, "       -c <count>     Number of packets to transmit (publisher only). Default 1\n");
    fprintf(stderr, "       -i <id>        Unique node ID among all publishers and subscribers. Legal value 1-1000. Default = 1\n");
    fprintf(stderr, "       -r <seed>      Random seed number. Default 1\n");
    fprintf(stderr, "       -d <drop-rate> Chance of sender dropping packet. 0.0 - never. 1.0 - always. Default 0.0\n");
    fprintf(stderr, "       -s <interval>  Time, in usec, to wait between each packet send. \n");
    fprintf(stderr, "       -j <jitter>    Max jitter, in usec, for send interval. Actual interval will be send-interval +- (0.0-1.0)*jitter. Default 0. \n");
    fprintf(stderr, "       -E <subscriber-count> Expected number of subscribers to connect before we start sending. Publisher only. Default 1 \n");
    fprintf(stderr, "       -e <node-id>   Expect packets from node_id. Legal value 1-1000. Susbscriber only. Can be repeated. Default 1 \n");
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
    pid_t ch_pid = 0;
    int rand_seed = 1;
    uint64_t packet_count = 1;
    rmc_context_id_t node_id = 1;
    float drop_rate = 0.0;
    int send_interval = 0;
    int jitter = 0;
    uint8_t expected_node_id[1024];
    int expect_node_id = 0;
    int expected_subscriber_count = 1;
    int e_arg_set = 0;

    strcpy(mcast_if_addr, MULTICAST_IF_ADDR_DEFAULT);
    strcpy(listen_if_addr, LISTEN_IF_ADDR_DEFAULT);
    strcpy(mcast_group_addr, MULTICAST_ADDR_DEFAULT);
    memset(expected_node_id, 0, sizeof(expected_node_id));

    while ((opt = getopt(argc, argv, "SP:M:m:l:p:c:n:r:s:j:d:e:E:")) != -1) {
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

        case 'i':
            node_id = atoi(optarg);
            break;

        case 'c':
            packet_count = atoll(optarg);
            break;

        case 'r':
            rand_seed = atoi(optarg);
            break;

        case 's':
            send_interval = atoi(optarg);
            break;

        case 'j':
            jitter = atoi(optarg);
            break;

        case 'd':
            drop_rate = atof(optarg);
            break;

        case 'E':
            expected_subscriber_count = atoi(optarg);

        case 'e':
            expect_node_id = atoi(optarg);
            if (expect_node_id < 1 || expect_node_id >= 1024) {
                usage(argv[0]);
                exit(1);
            }
            expected_node_id[expect_node_id] = 1;
            e_arg_set = 1;
            break;

        default: /* '?' */
            usage(argv[0]);
            exit(1);
        }
    }
    
           
    // Default 
    if (!e_arg_set)
        expected_node_id[1] = 1;
    
    run_list_tests();
    test_packet_interval();
    test_circular_buffer();
    test_pub(); 
    test_sub();
    setlinebuf(stdout);
    setlinebuf(stderr);

    if (!publisher) {
        puts("SUBSCRIBER\n");
        test_rmc_proto_sub(mcast_group_addr,
                           mcast_if_addr,
                           mcast_port,
                           node_id,
                           expected_node_id,
                           sizeof(expected_node_id) / sizeof(expected_node_id[0]));
        exit(0);
    }


    setlinebuf(stdout);
    setlinebuf(stderr);
    puts("PUBLISHER\n");
    test_rmc_proto_pub(mcast_group_addr,
                       mcast_if_addr,
                       listen_if_addr,
                       mcast_port,
                       listen_port,
                       node_id,
                       packet_count,
                       expected_subscriber_count,
                       rand_seed,
                       send_interval,
                       jitter,
                       drop_rate);

    exit(0);
} 
