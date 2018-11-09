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

typedef uint32_t rmc_context_id_t;

typedef struct multicast_header {
    rmc_context_id_t context_id;
    payload_len_t payload_len;
    uint32_t listen_ip; // In host format
    uint16_t listen_port;
} multicast_header_t;

typedef struct cmd_ack_single {
    packet_id_t packet_id; // Packet ID to ac
} cmd_ack_single_t;

typedef struct cmd_ack_interval {
    packet_id_t first;    // ID of first packet ID
    packet_id_t last;     // ID of last packet ID
} cmd_ack_interval_t;


typedef struct cmd_packet_header {
    packet_id_t pid;    // ID of first packet ID
    payload_len_t payload_len;
} cmd_packet_header_t;


// Max UDP size is 0xFFE3 (65507). Subtract 0x20 (32) bytes for RMC
// header data.
#define RMC_MAX_PACKET 0xFFE3
#define RMC_MAX_PAYLOAD 0xFFC3


// Probably needs to be a lot bigger in high
// throughput situations.
#define RMC_MAX_TCP_PENDING_WRITE 0xFFFF 
#define RMC_MAX_CONNECTIONS 16
#define RMC_LISTEN_SOCKET_BACKLOG 5
#define RMC_DEFAULT_PACKET_TIMEOUT 5000000

#define RMC_POLLREAD 0x01
#define RMC_POLLWRITE 0x02
#define RMC_MULTICAST_RECV_INDEX 0xFFFFFFFD
#define RMC_MULTICAST_SEND_INDEX 0xFFFFFFFE
#define RMC_LISTEN_INDEX 0xFFFFFFFF



#define RMC_CONNECTION_MODE_UNUSED 0
#define RMC_CONNECTION_MODE_SUBSCRIBER 1
#define RMC_CONNECTION_MODE_PUBLISHER 2
// Socket is being connected.
#define RMC_CONNECTION_MODE_CONNECTING 3

typedef uint32_t rmc_connection_index_t;
typedef uint16_t rmc_poll_action_t;
typedef struct rmc_connection {
    // Index of owner rmc_connection_t struct in the master
    // rmc_context_t::connections[] array.
    // rmc_context_t::connections[rmc_index].poll_info is this struct.
    // Special cases on RMC_MULTICAST_INDEX and RMC_LISTEN_INDEX
    // to identify the multicast and listen descriptors used
    // by rmc_context_t;x
    rmc_connection_index_t rmc_index;

    // Action is a bitmask of RMC_POLLREAD and RMC_POLLWRITE
    rmc_poll_action_t action;

    // Socket TCP descriptor
    int descriptor;

    // Circular buffer of pending data read.
    circ_buf_t read_buf;

    // backing buffer for circ_buf above.  circ_buf_data and circ_buf
    // are tied toegther through the circ_buf_init() call.
    // One byte extra needed by circ buf for housekeeping reasons.
    // FIXME: Use shared circular buffer across all rmc_connections for both read and write.
    uint8_t read_buf_data[RMC_MAX_PAYLOAD + 1]; 

    // Circular buffer of pending data read.
    circ_buf_t write_buf;
    uint8_t write_buf_data[RMC_MAX_TCP_PENDING_WRITE]; 

    // RMC_CONNECTION_MODE_PUBLISHER   The connection is used to publish acks and resend packets 
    // RMC_CONNECTION_MODE_SUBSCRIBER  The connection is used to subscribe to acks and resends
    // RMC_CONNECTION_MODE_OTHER       The connection is used for multicast or TCP listen.
    // RMC_CONNECTION_MODE_CONNECTING  The outbound connection is being setup.
    uint8_t mode;

    in_port_t remote_port;    // In host format
    uint32_t remote_address;  // In host format

    // Subscriber and publishers to to manage inflight packets for this connection.
    // The union member to use is specified by the 'mode' member.
    //
    // 'subscriber' is used when the connection was accepted by _process_accept()
    // and we take on the role as a publisher of packets.
    // Added to rmc_context_t::pub_ctx in rmc_init_context() through a
    // pub_init_subscriber() call.
    // pub_subscriber_t::user_data of the subscriber points back to this
    // struct.
    //
    // 'publisher' is used when we connected to a publisher in _process_multicast_read()
    // as we receive a packet from a previously unknown sender (publisher) that
    // we need to connect a TCP connection to in order to do ack and resend management.
    // Added to rmc_context_t::sub_ctx in rmc_init_context() through a
    // sub_init_publisher() call.
    // sub_publisher_t::user_data of the subscriber points back to this
    // struct.
    //
    union {
        pub_subscriber_t subscriber;
        sub_publisher_t publisher;
    } pubsub;

    // Owning context
    struct rmc_context* owner;
} rmc_connection_t;


// A single context.
typedef struct rmc_context {
    pub_context_t pub_ctx;
    sub_context_t sub_ctx;
    int connection_count;

    // Top connection index currently in use.
    rmc_connection_index_t max_connection_ind;  
    rmc_connection_t connections[RMC_MAX_CONNECTIONS]; //
    user_data_t user_data;

    in_addr_t mcast_if_addr; // In host format (little endian)
    in_addr_t listen_if_addr; // In host format
    in_addr_t mcast_group_addr; // In host format
    int mcast_port; // Must be same for all particants.
 
    // Must be different for each process on same machine.
    // Multiple contexts within a single program can share listen port
    // to do load distribution on incoming connections
    int listen_port; 

    int mcast_recv_descriptor;
    int mcast_send_descriptor;

    int listen_descriptor;

    
    // Randomly genrated context ID allowing us to recognize and drop
    // looped back multicast messages.
    rmc_context_id_t context_id; 

    // When we start sending packets via TCP.
    uint32_t resend_timeout;

    // When we want to know if a connection can be written to or read from
    void (*poll_add)(struct rmc_context* context,
                     int descriptor,
                     rmc_connection_index_t index,
                     rmc_poll_action_t initial_action);

    // We have changed the action bitmap.
    void (*poll_modify)(struct rmc_context* context,
                        int descriptor,
                        rmc_connection_index_t index,
                        rmc_poll_action_t old_action,
                        rmc_poll_action_t new_action);

    // Callback when we don't need connection ready notifications.
    void (*poll_remove)(struct rmc_context* context,
                        int descriptor,
                        rmc_connection_index_t index);

    
    // Called to alloc memory for incoming data.
    // that needs to be processed.
    void* (*sub_payload_alloc)(payload_len_t payload_len,
                               user_data_t user_data);

    // Callback to free memory for packets that has been
    // successfully sent out.
    void (*pub_payload_free)(void* payload,
                             payload_len_t payload_len,
                             user_data_t user_data);


} rmc_context_t;


// All functions return error codes from error
extern int rmc_init_context(rmc_context_t* context,
                            // Domain name or IP of multicast group to join.
                            char* multicast_group_addr,  

                            // IP address to listen to for incoming subscription
                            // connection from subscribers receiving multicast packets
                            // Default if 0 ptr: "0.0.0.0" (IFADDR_ANY)
                            char* multicast_iface_addr, 

                            // IP address to listen to for incoming subscription
                            // connection from subscribers receiving multicast packets
                            // Default if 0 ptr: "0.0.0.0" (IFADDR_ANY)
                            char* listen_iface_addr, 

                            int multicast_port, 

                            int listen_port, 

                            // User data that can be extracted with rmc_user_data(.                            
                            // Typical application is for the poll and memory callbacks below
                            // to tie back to its structure using the provided
                            // pointer to the invoking rmc_context_t structure.
                            user_data_t user_data,

                            // Called when a new connection is created by rmc.
                            //
                            // poll->action & RMC_POLLREAD
                            // specifies that we want rmc_write() to
                            // be called (with poll->rmc_index as an
                            // argument) when the connection can be
                            // written to (asynchronously).
                            //
                            // poll->action & RMC_POLLWRITE
                            // specifies that we want rmc_write() to
                            // be called (with poll->rmc_index as an
                            // argument) when the connection can be
                            // written to (asynchronously).
                            //

                            void (*poll_add)(struct rmc_context* context,
                                             int descriptor,
                                             rmc_connection_index_t index,
                                             rmc_poll_action_t initial_action),
                            
                            // The poll action either needs to be re-armed 
                            // in cases where polling is oneshot (epoll(2) with EPOLLONESHOT),
                            // or the poll action has changed.
                            //
                            // Rearming can be detected by checking if
                            // old_action == rmc_connection_action(sock);
                            //
                            void (*poll_modify)(struct rmc_context* context,
                                                int descriptor,
                                                rmc_connection_index_t index,
                                                rmc_poll_action_t old_action,
                                                rmc_poll_action_t new_action),



                            // Callback to remove a connection previously added with poll_add().
                            void (*poll_remove)(struct rmc_context* context,
                                                int descriptor,
                                                rmc_connection_index_t index),




                            // Callback to allocate payload memory used to store
                            // incoming packages. Called via rmc_read() when
                            // a new multicast or tcp payload packet is delivered.
                            //
                            // The allocated memory has to manually freed by the caller
                            // after an rmc_packet_dispatched() has been called to
                            // mark the packet as processed.
                            //
                            // If set to 0, malloc() will be used.
                            void* (*sub_payload_alloc)(payload_len_t payload_len,
                                                       user_data_t user_data),

                            // Callback to previously allocated memory provided
                            // by the caller of rmc_queue_packet().
                            //
                            // Invoked by rmc_read() when an ack has been collected
                            // from all subscribers.
                            //
                            // If set 0, free() will be used.
                            void (*pub_payload_free)(void* payload,
                                                     payload_len_t payload_len,
                                                     user_data_t user_data));


extern int rmc_activate_context(rmc_context_t* context);

extern int rmc_deactivate_context(rmc_context_t* context);

extern int rmc_connect_subscription(rmc_context_t* context,
                                    char* server_addr,
                                    int server_port,
                                    int* result_connection,
                                    int* result_connection_index);

extern int rmc_set_user_data(rmc_context_t* ctx, user_data_t user_data);
extern user_data_t rmc_user_data(rmc_context_t* ctx);
extern rmc_context_id_t rmc_context_id(rmc_context_t* ctx);

extern int rmc_get_next_timeout(rmc_context_t* context, usec_timestamp_t* result);
extern int rmc_process_timeout(rmc_context_t* context);

// If a valid pointer, res will be set to:

// An error occurred, check return value
#define RMC_READ_ERROR 0

// Multicast package was received
#define RMC_READ_MULTICAST 1

// A multicast loopback message, sent by self, was detected and
// discarded
#define RMC_READ_MULTICAST_LOOPBACK 2

// Multicast package was received from a new publisher. Discarded, but
// a tcp connection is being setup to publisher
#define RMC_READ_MULTICAST_NEW 3

// Multicast package was received from a publisher. Discarded since
// tcp connection is not yet complete
#define RMC_READ_MULTICAST_NOT_READY 4

// TCP Data was read and processed.
#define RMC_READ_TCP 5

// TCP accept was processed.
#define RMC_READ_ACCEPT 6


extern int rmc_read(rmc_context_t* context, rmc_connection_index_t rmc_index, uint8_t* res);
extern int rmc_write(rmc_context_t* context, rmc_connection_index_t rmc_index);
extern int rmc_queue_packet(rmc_context_t* context, void* payload, payload_len_t payload_len);
extern int rmc_get_poll_size(rmc_context_t* context, int *result);
extern int rmc_get_poll_vector(rmc_context_t* context, rmc_connection_t* result, int* len);
extern int rmc_get_poll(rmc_context_t* context, int rmc_index, rmc_connection_t* result);
extern int rmc_get_ready_packet_count(rmc_context_t* context);
extern sub_packet_t* rmc_get_next_ready_packet(rmc_context_t* context);

// CALLER STILL HAS TO FREE packet->payload!
extern int rmc_packet_dispatched(rmc_context_t* context, sub_packet_t* packet);

// FIXME: MOVE TO INTERNAL HEADER FILE
extern void rmc_reset_connection(rmc_connection_t* sock, int index);

extern int rmc_connect_tcp_by_address(rmc_context_t* ctx,
                                      in_addr_t address,
                                      in_port_t port,
                                      rmc_connection_index_t* result_index);

extern int rmc_connect_tcp_by_host(rmc_context_t* ctx,
                                   char* server_addr,
                                   in_port_t port,
                                   rmc_connection_index_t* result_index);

extern int rmc_process_accept(rmc_context_t* ctx,
                              rmc_connection_index_t* result_index);

extern int rmc_close_tcp(rmc_context_t* ctx, rmc_connection_index_t s_ind);
extern int rmc_proto_ack(rmc_context_t* ctx, sub_packet_t* pack);

extern int rmc_complete_connect(rmc_context_t* ctx, rmc_connection_t* sock);
#endif // __RMC_PROTO_H__
