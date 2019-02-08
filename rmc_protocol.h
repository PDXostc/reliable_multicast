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
#define RMC_CMD_CONTROL_MESSAGE 3


typedef struct  __attribute__((packed))
packet_header {
    packet_id_t pid;               // 8 bytes  Packet ID
    rmc_node_id_t node_id;         // 4 bytes  Publisher Node ID
    payload_len_t payload_len;     // 2 bytes  Payload len
    uint32_t listen_ip;            // 4 bytes  Publisher control ip address
    uint16_t listen_port;          // 2 bytes  Publisher control port
} packet_header_t;                 // 20 bytes


typedef struct  __attribute__((packed))
cmd_ack_interval {
    packet_id_t first_pid;    // ID of first packed ID
    packet_id_t last_pid;     // ID of last packed ID
} cmd_ack_interval_t;

typedef struct  __attribute__((packed))
cmd_control_message {
    uint16_t payload_len;
    uint8_t payload[];
} cmd_control_message_t;

#endif
