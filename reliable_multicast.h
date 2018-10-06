// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)


#ifndef __REL_MCAST_H__
#define __REL_MCAST_H__
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include "list.h"

typedef uint64_t packet_id_t

typedef uint16_t payload_len_t

typedef struct packet {
    packet_id_t id;
    uint8_t payload[];
} packet_t;

enum command {
    CMD_INIT = 0,
    CMD_INIT_REPLY = 1,
    CMD_PACKET = 2,
    CMD_ACK = 3,
};

typedef struct cmd {
    uint8_t command;
    uint8_t data[];
} cmd_t;

//
// Init
//
typedef struct cmd_init {
    uint8_t version; // Version supported;
} cmt_init_t;

//
// Init reply
//
typedef struct cmd_init_reply {
    uint8_t version; // Version supported;
    packet_id_t last_sent; // ID of last sent packet.
} cmt_init_t;


//
// Single packet
//
typedef struct cmd_packet {
    packet_id_t packet_id; // Packet ID in payload
    payload_len_t length;    // Payload length of data[]
    uint8_t data[];
} cmt_init_t;


// 
// Ack one or more packets
//
typedef struct cmd_ack {
    payload_len_t length;    // Payload length of data[]
    uint8_t data[];       // One or more block data elements
} cmt_init_t;

enum ack_block {
    BLOCK_SINGLE = 0,
    BLOCK_MULTI = 1,
    BLOCK_MULTI_BITMAP = 2
};

typedef struct cmd_ack_block {
    uint8_t block_type;     // See enum above.
    uint8_t data[];    
} cmd_ack_block_t;
 
typedef struct cmd_ack_block_single {
    packet_id_t packet_id;
} cmd_ack_block_single_t;

typedef struct cmd_ack_multi {
    packet_id_t first; // ID of first packet ID 
    packet_id_t last; // ID of last packet ID
} cmd_ack_block_multi_t;

typedef struct cmd_ack_block_bitmap {
    packet_id_t first; // ID of first packet in bitmap
    payload_len_t length; // Number of bytes in 'data' bitmap
    uuint8_t data[];
} cmd_ack_block_bitmap_t;

#endif // __DSTC_H__
