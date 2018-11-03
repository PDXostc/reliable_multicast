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

#define RMC_CMD_PACKET 1
#define RMC_CMD_ACK_SINGLE 2
#define RMC_CMD_ACK_INTERVAL 3

typedef struct cmd_ack_single {
    packet_id_t packet_id; // Packet ID to ac
} cmd_ack_single_t;

typedef struct cmd_ack_interval {
    packet_id_t first;    // ID of first packet ID
    packet_id_t last;     // ID of last packet ID
} cmd_ack_interval_t;


typedef struct cmd_packet {
    packet_id_t pid;    // ID of first packet ID
    payload_len_t payload_len;
    uint8_t payload[];
} cmd_packet_t;


// Max UDP size is 0xFFE3 (65507). Subtract 0x20 (32) bytes for RMC
// header data.
#define RMC_MAX_PACKET 0xFFE3
#define RMC_MAX_PAYLOAD 0xFFC3

// Probably needs to be a lot bigger in high
// throughput situations.
#define RMC_MAX_TCP_PENDIONG_WRITE 0xFFFF 
#define RMC_MAX_SOCKETS 16
#define RMC_LISTEN_SOCKET_BACKLOG 5

typedef uint32_t rmc_poll_index_t;

#define RMC_POLLREAD 0x01
#define RMC_POLLWRITE 0x02
#define RMC_MULTICAST_RECV_INDEX 0xFFFFFFFD
#define RMC_MULTICAST_SEND_INDEX 0xFFFFFFFE
#define RMC_LISTEN_INDEX 0xFFFFFFFF


typedef struct rmc_poll {
    // Index of owner rmc_socket_t struct in the master
    // rmc_context_t::sockets[] array.
    // rmc_context_t::sockets[rmc_index].poll_info is this struct.
    // Special cases on RMC_MULTICAST_INDEX and RMC_LISTEN_INDEX
    // to identify the multicast and listen descriptors used
    // by rmc_context_t;x
    rmc_poll_index_t rmc_index;

    // Action is a bitmask of RMC_POLLREAD and RMC_POLLWRITE
    uint16_t action;

    // Socket TCP descriptor
    int descriptor;
} rmc_poll_t;


#define RMC_SOCKET_MODE_UNUSED 0
#define RMC_SOCKET_MODE_SUBSCRIBER 1
#define RMC_SOCKET_MODE_PUBLISHER 2
// Socket is being connected.
#define RMC_SOCKET_MODE_CONNECTING 3

typedef struct rmc_socket {
    // See above.
    rmc_poll_t poll_info;


    // Circular buffer of pending data read.
    circ_buf_t read_buf;

    // backing buffer for circ_buf above.  circ_buf_data and circ_buf
    // are tied toegther through the circ_buf_init() call.
    // One byte extra needed by circ buf for housekeeping reasons.
    // FIXME: Use shared circular buffer across all rmc_sockets for both read and write.
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

    // Top socket index currently in use.
    rmc_poll_index_t max_socket_ind;  
    rmc_socket_t sockets[RMC_MAX_SOCKETS]; //
    user_data_t user_data;

    int port; // Used both for TCP listen and mcast.
    char multicast_addr[256];
    char multicast_if_ip[80];
    struct sockaddr_in mcast_local_addr;
    struct sockaddr_in mcast_dest_addr;

    int mcast_recv_descriptor;
    int mcast_send_descriptor;

    char listen_if_ip[80];
    int listen_descriptor;

    // Once we have sent a packet how long do we wait for an ack, in usec, until
    // we resend it?
    uint32_t resend_timeout;

    // When we want to know if a socket can be written to or read from
    void (*poll_add)(struct rmc_context* context, rmc_poll_t* poll);

    // We have changed the action bitmap.
    void (*poll_modify)(struct rmc_context* context,
                        rmc_poll_t* old_poll,
                        rmc_poll_t* new_poll);

    // Callback when we don't need socket ready notifications.
    void (*poll_remove)(struct rmc_context* context, rmc_poll_t* poll);

    // Called to alloc memory for incoming data.
    void* (*payload_alloc)(struct rmc_context* context, payload_len_t payload_len);
    
    // Free payload provided by rmc_queue_packet()
    void (*payload_free)(struct rmc_context* context, void* payload, payload_len_t payload_len);
} rmc_context_t;


// All functions return error codes from error
extern int rmc_init_context(rmc_context_t* context,
                            char* multicast_addr,  // Domain name or IP

                            // Interface IP to bind mcast to. Must be set.
                            char* multicast_if_ip, 

                            // IP address to listen to for incoming subscription
                            // connection from subscribers receiving multicast packets
                            char* listen_if_ip, 

                            int port, // Used for local listen TCP and multicast port

                            // User data that can be extracted with rmc_user_data(.
                            
                            // Typical application is for the poll and memory callbacks below
                            // to tie back to its structure using the provided
                            // pointer to the invoking rmc_context_t structure.
                            user_data_t user_data,

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

                            void (*poll_add)(struct rmc_context* context, rmc_poll_t* poll),
                            
                            // The poll action either needs to be re-armed 
                            // in cases where polling is oneshot (epoll(2) with EPOLLONESHOT),
                            // or the poll action has changed.
                            //
                            // Rearming can be detected by checking if
                            // old->action == new_poll->action.
                            //
                            void (*poll_modify)(struct rmc_context* context,
                                                rmc_poll_t* old_poll,
                                                rmc_poll_t* new_poll),

                            // Callback to remove a socket previously added with poll_add().
                            void (*poll_remove)(struct rmc_context* context, rmc_poll_t* poll),

                            // Function to call to allocated payload memory specified
                            // by queue_packet()
                            // Also called to allocate memory for incoming
                            // packets read, which will be pointed to
                            // by rmc_get_next_ready_packet(.., void* payload)
                            void* (*payload_alloc)(struct rmc_context* context, payload_len_t payload_len),

                            // Function called to free payload pointed to by
                            // rmc_queue_packet(). Will be invoked by rmc_write()
                            // when payload has been successfully sent.
                            void (*payload_free)(struct rmc_context* context,
                                                 void* payload,
                                                 payload_len_t payload_len));


extern int rmc_activate_context(rmc_context_t* context);

extern int rmc_deactivate_context(rmc_context_t* context);

extern int rmc_connect_subscription(rmc_context_t* context,
                                    char* server_addr,
                                    int server_port,
                                    int* result_socket,
                                    int* result_connection_index);

extern int rmc_set_user_data(rmc_context_t* ctx, user_data_t user_data);
extern user_data_t rmc_user_data(rmc_context_t* ctx);

extern int rmc_get_next_timeout(rmc_context_t* context, usec_timestamp_t* result);
extern int rmc_process_timeout(rmc_context_t* context);

extern int rmc_read(rmc_context_t* context, rmc_poll_index_t rmc_index);
extern int rmc_write(rmc_context_t* context, rmc_poll_index_t rmc_index);
extern int rmc_queue_packet(rmc_context_t* context, void* payload, payload_len_t payload_len);
extern int rmc_get_poll_size(rmc_context_t* context, int *result);
extern int rmc_get_poll_vector(rmc_context_t* context, rmc_poll_t* result, int* len);
extern int rmc_get_poll(rmc_context_t* context, int rmc_index, rmc_poll_t* result);
extern int rmc_get_ready_packet_count(rmc_context_t* context);
extern sub_packet_t* rmc_get_next_ready_packet(rmc_context_t* context);
extern int rmc_free_packet(rmc_context_t* context, sub_packet_t* packet);

// FIXME: MOVE TO INTERNAL HEADER FILE
extern void rmc_reset_socket(rmc_socket_t* sock, int index);

extern int rmc_connect_tcp_by_address(rmc_context_t* ctx,
                                      struct sockaddr_in* sock_addr,
                                      rmc_poll_index_t* result_index);

extern int rmc_connect_tcp_by_host(rmc_context_t* ctx,
                                   char* server_addr,
                                   rmc_poll_index_t* result_index);

extern int rmc_process_accept(rmc_context_t* ctx,
                              rmc_poll_index_t* result_index);

extern int rmc_close_tcp(rmc_context_t* ctx, rmc_poll_index_t p_ind);
extern int rmc_proto_ack(rmc_context_t* ctx,
                         rmc_socket_t* sock,
                         sub_packet_t* pack);

extern int rmc_complete_connect(rmc_context_t* ctx, rmc_socket_t* sock);
#endif // __RMC_PROTO_H__
