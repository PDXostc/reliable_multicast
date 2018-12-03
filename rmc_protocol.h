// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#ifndef __RMC_PROTOCOL_H__
#define __RMC_PROTOCOL_H__
#include "rmc_common.h"


#define RMC_CMD_PACKET 1
#define RMC_CMD_ACK_INTERVAL 2


typedef struct  __attribute__((packed))
multicast_header {
    rmc_context_id_t context_id;
    payload_len_t payload_len;
    uint32_t listen_ip; // In host format
    uint16_t listen_port;
} multicast_header_t;


typedef struct  __attribute__((packed))
cmd_packet_header {
    packet_id_t pid;    // ID of first packed ID
    payload_len_t payload_len;
} cmd_packet_header_t;

typedef struct  __attribute__((packed))
cmd_ack_interval {
    packet_id_t first_pid;    // ID of first packed ID
    packet_id_t last_pid;     // ID of last packed ID
} cmd_ack_interval_t;

#endif



