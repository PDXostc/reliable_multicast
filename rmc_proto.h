// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)


#ifndef __RMC_PROTO_H__
#define __RMC_PROTO_H__
#include "rmc_common.h"
#include "circular_buffer.h"
#include "rmc_pub.h"
#include "rmc_sub.h"
#include <netinet/in.h>


typedef struct packet {
    packet_id_t id;
    payload_len_t len;
    uint8_t payload[];
} packet_t;

#define RMC_CMD_INIT 0
#define RMC_CMD_INIT_REPLY 1
#define RMC_CMD_PACKET 2
#define RMC_CMD_ACK 3


typedef struct cmd {
    uint8_t command;
    payload_len_t length;
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

// Max UDP size is 0xFFE3 (65507). Subtract 0x20 (32) bytes for RMC
// header data.
#define RMC_MAX_PACKET 0xFFE3
#define RMC_MAX_PAYLOAD 0xFFC3

// Probably needs to be a lot bigger in high
// throughput situations.
#define RMC_MAX_TCP_PENDIONG_WRITE 0xFFFF 

#define RMC_MAX_SOCKETS 256

#define RMC_MULTICAST_SOCKET_INDEX 0
#define RMC_LISTEN_SOCKET_INDEX 1
#define RMC_LISTEN_SOCKET_BACKLOG 5

typedef uint32_t rmc_poll_index_t;

typedef struct rmc_poll {
    uint16_t action;

    // Index of owner rmc_socket_t struct in the master
    // rmc_context_t::sockets[] array.
    // rmc_context_t::sockets[rmc_index].poll_info is this struct.
    rmc_poll_index_t rmc_index;
} rmc_poll_t;

#define RMC_SOCKET_MODE_UNUSED 0
#define RMC_SOCKET_MODE_SUBSCRIBER 1
#define RMC_SOCKET_MODE_PUBLISHER 2
#define RMC_SOCKET_MODE_OTHER 3
typedef struct rmc_socket {
    // See above.
    rmc_poll_t poll_info;

    // Socket TCP descriptor
    int descriptor;

    // Circular buffer of pending data read.
    circ_buf_t read_buf;

    // backing buffer for circ_buf above.  circ_buf_data and circ_buf
    // are tied toegther through the circ_buf_init() call.
    // One byte extra needed by circ buf for housekeeping reasons.
    uint8_t read_buf_data[RMC_MAX_PAYLOAD + 1]; 

    // Circular buffer of pending data read.
    circ_buf_t write_buf;
    uint8_t write_buf_data[RMC_MAX_TCP_PENDIONG_WRITE]; 

    // RMC_SOCKET_MODE_PUBLISHER   The socket is used to publish acks and resend packets 
    // RMC_SOCKET_MODE_SUBSCRIBER  The socket is used to subscribe to acks and resends
    // RMC_SOCKET_MODE_OTHER       The socket is used for multicast or TCP listen.
    uint8_t mode;

    struct sockaddr_in remote_address;

    // Subscriber and publishers to to manage inflight packets for this socket.
    // The union member to use is specified by the 'mode' member.
    // 
    //
    // 'subscriber' is used when the socket was accepted by _process_accept()
    // and we take on the role as a publisher of packets.
    // Added to rmc_context_t::pub_ctx in rmc_init_context() through a
    // pub_init_subscriber() call.
    // pub_subscriber_t::user_data of the subscriber points back to this
    // struct.
    //
    // 'publisher' is used when we connected to a publisher in _process_multicast_read()
    // as we receive a packet from a previously unknown sender (publisher) that
    // we need to connect a TCP socket to in order to do ack and resend management.
    // Added to rmc_context_t::sub_ctx in rmc_init_context() through a
    // sub_init_publisher() call.
    // sub_publisher_t::user_data of the subscriber points back to this
    // struct.
    //
    union {
        pub_subscriber_t subscriber;
        sub_publisher_t publisher;
    } pubsub;

} rmc_socket_t;

#define RMC_RESEND_TIMEOUT_DEFAULT 500000

typedef struct rmc_context {
    pub_context_t pub_ctx;
    sub_context_t sub_ctx;
    int socket_count;
    int max_socket_ind;  // Max socket index currently in use.
    rmc_socket_t sockets[RMC_MAX_SOCKETS]; //
    char multicast_addr[256];
    struct sockaddr_in mcast_dest_addr;
    char listen_ip[80];
    int port;
    // Once we have sent a packet how long do we wait for an ack, in usec, until
    // we resend it?
    uint32_t resend_timeout;

    void (*poll_add)(rmc_poll_t* poll); // When we want to know if a socket can be written to or read from
    void (*poll_modify)(rmc_poll_t* poll); // We have changed the action bitmap.
    void (*poll_remove)(rmc_poll_t* poll);  // Callback when we don't need socket ready notifications.
    void* (*payload_alloc)(payload_len_t payload_len);  // Called to alloc memory for incoming data.
    void (*payload_free)(void* payload, payload_len_t payload_len);  // Free payload provided by rmc_queue_packet()
} rmc_context_t;

#define RMC_POLLREAD 0x01
#define RMC_POLLWRITE 0x02


// All functions return error codes from error
extern int rmc_init_context(rmc_context_t* context,
                            char* multicast_addr,  // Domain name or IP
                            char* listen_ip, // For subscription management. TCP
                            int port, // Used for local listen IP and multicast port

                            // Function to call to allocated payload memory specified
                            // by queue_packet()
                            // Also called to allocate memory for incoming
                            // packets read, which will be pointed to
                            // by rmc_get_next_ready_packet(.., void* payload)
                            void* (*payload_alloc)(payload_len_t payload_len),

                            // Function called to free payload pointed to by
                            // rmc_queue_packet(). Will be invoked by rmc_write()
                            // when payload has been successfully sent.
                            void (*payload_free)(void* payload, payload_len_t payload_len),

                            // Called when a new socket is created by rmc.
                            //
                            // poll->action & RMC_POLLREAD
                            // specifies that we want rmc_write() to
                            // be called (with poll->rmc_index as an
                            // argument) when the socket can be
                            // written to (asynchronously).
                            //
                            // poll->action & RMC_POLLWRITE
                            // specifies that we want rmc_write() to
                            // be called (with poll->rmc_index as an
                            // argument) when the socket can be
                            // written to (asynchronously).
                            //
                            void (*poll_add)(rmc_poll_t* poll),

                            // Callback to remove a socket previously added with poll_add().
                            void (*poll_remove)(rmc_poll_t* poll));


extern int rmc_activate_context(rmc_context_t* context);

extern int rmc_deactivate_context(rmc_context_t* context);

extern int rmc_connect_subscription(rmc_context_t* context,
                                    char* server_addr,
                                    int server_port,
                                    int* result_socket,
                                    int* result_connection_index);

extern int rmc_get_next_timeout(rmc_context_t* context, usec_timestamp_t* result);
extern int rmc_process_timeout(rmc_context_t* context);

extern int rmc_read(rmc_context_t* context, rmc_poll_index_t rmc_index, uint16_t* new_poll_action);
extern int rmc_write(rmc_context_t* context, rmc_poll_index_t rmc_index, uint16_t* new_poll_action);
extern int rmc_queue_packet(rmc_context_t* context, void* payload, payload_len_t payload_len);
extern int rmc_get_poll_size(rmc_context_t* context, int *result);
extern int rmc_get_poll_vector(rmc_context_t* context, rmc_poll_t* result, int* len);
extern int rmc_get_poll(rmc_context_t* context, int rmc_index, rmc_poll_t* result);
extern int rmc_get_ready_packet_count(rmc_context_t* context);
extern sub_packet_t* rmc_get_next_ready_packet(rmc_context_t* context);
extern void rmc_free_packet(sub_packet_t* packet);

#endif // __RMC_PROTO_H__
