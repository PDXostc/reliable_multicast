// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)


#ifndef __REL_MCAST_PROTO_H__
#define __REL_MCAST_PROTO_H__
#include "rmc_common.h"
#include "rmc_pub.h"
#include "rmc_sub.h"


typedef struct packet {
    packet_id_t id;
    payload_len_t len;
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
} cmt_init_reply_t;


// 
// Ack one or more packets
//
typedef struct cmd_ack {
    payload_len_t length;    // Payload length of data[]
    uint8_t data[];       // One or more block data elements
} cmt_ack_t;

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
    uint8_t data[];
} cmd_ack_block_bitmap_t;

#define RMC_MAX_PAYLOAD 0x10000
#define RMC_MAX_SUBSCRIPTIONS 1024


typedef struct rmc_context {
    pub_context_t pub_ctx;
    sub_context_t sub_ctx;
    int socket_count;
    int sockets[RMC_MAX_SUBSCRIPTIONS];
    char multicast_addr[256];
    int multicast_port;
    char listen_ip[80];
    int listen_port;
    void (*socket_added)(int, int); // Callback for each socket opened
    void (*socket_deleted)(int, int);  // Callback for each socket closed.
    void* (*payload_alloc)(payload_len_t payload_len);  // Free payload provided by rmc_queue_packet()
    void (*payload_free)(void* payload, payload_len_t payload_len);  // Free payload provided by rmc_queue_packet()
} rmc_context_t;



// All functions return error codes from error
extern int rmc_init(rmc_context_t* context,
                    char* multicast_addr,  // Domain name or IP
                    int multicast_port,
                    char* listen_ip, // For subscription management. TCP
                    int listen_port, // For subscription management
                    // Funcation to call to free memory specified
                    // by queue_packet(...,payload,payload_len)
                    void* (*payload_alloc)(payload_len_t payload_len),
                    void (*payload_free)(void* payload, payload_len_t payload_len),
                    void (*socket_added)(int socket, int connection_index), // Callback for each socket opened
                    void (*socket_deleted)(int socket, int  connection_index));  // Callback for each socket closed.

extern int rmc_listen(rmc_context_t* context);

extern int rmc_connect(rmc_context_t* context,
                       char* server_ip,
                       int server_port);


extern int rmc_read(rmc_context_t* context, int connection_index);
extern int rmc_write(rmc_context_t* context, int connection_index);
extern int rmc_queue_packet(rmc_context_t* context, void* payload, payload_len_t payload_len);
extern int rmc_get_socket_count(rmc_context_t* context, int *result);
extern int rmc_get_sockets(rmc_context_t* context, int* sockets, int* max_len);
extern int rmc_read_tcp(rmc_context_t* context);
extern int rmc_read_multicast(rmc_context_t* context);
extern int rmc_get_ready_packet_count(rmc_context_t* context);
extern int rmc_get_packet(rmc_context_t* context, void** packet, int* payload_len);

#endif // __DSTC_H__
