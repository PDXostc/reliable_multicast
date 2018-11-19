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
#define RMC_LISTEN_SOCKET_BACKLOG 5
#define RMC_DEFAULT_PACKET_TIMEOUT 100000
#define RMC_DEFAULT_ACK_TIMEOUT 50000 // 50 msec.

#define RMC_POLLREAD 0x01
#define RMC_POLLWRITE 0x02
#define RMC_MULTICAST_INDEX 0xFFFFFFFE
#define RMC_LISTEN_INDEX 0xFFFFFFFF



#define RMC_CONNECTION_MODE_UNUSED 0
#define RMC_CONNECTION_MODE_SUBSCRIBER 1
#define RMC_CONNECTION_MODE_PUBLISHER 2
// Socket is being connected.
#define RMC_CONNECTION_MODE_CONNECTING 3


typedef uint32_t rmc_connection_index_t;
typedef uint16_t rmc_poll_action_t;

// Called when a new connection is created by rmc.
//
// poll->action & RMC_POLLREAD
// specifies that we want rmc_write() to
// be called (with poll->connection_index as an
// argument) when the connection can be
// written to (asynchronously).
//
// poll->action & RMC_POLLWRITE
// specifies that we want rmc_write() to
// be called (with poll->connection_index as an
// argument) when the connection can be
// written to (asynchronously).
//
typedef void (*rmc_poll_add_cb_t)(user_data_t user_data,
                                  int descriptor,
                                  rmc_connection_index_t index,
                                  rmc_poll_action_t initial_action);

// The poll action either needs to be re-armed 
// in cases where polling is oneshot (epoll(2) with EPOLLONESHOT),
// or the poll action has changed.
//
// Rearming can be detected by checking if
// old_action == rmc_connection_action(sock);
//
typedef void (*rmc_poll_modify_cb_t)(user_data_t user_data,
                                     int descriptor,
                                     rmc_connection_index_t index,
                                     rmc_poll_action_t old_action,
                                     rmc_poll_action_t new_action);



// Callback to remove a connection previously added with poll_add().
typedef void (*rmc_poll_remove_cb_t)(user_data_t user_data,
                                     int descriptor,
                                     rmc_connection_index_t index);

typedef struct rmc_connection {
    // Index of owner rmc_connection_t struct in the master
    // rmc_context_t::connections[] array.
    // rmc_context_t::connections[connection_index].poll_info is this struct.
    // Special cases on RMC_MULTICAST_INDEX and RMC_LISTEN_INDEX
    // to identify the multicast and listen descriptors used
    // by rmc_context_t;x
    rmc_connection_index_t connection_index;

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
} rmc_connection_t;


// Maximum number of subscribers an rmc_pub_context_t can have.
// Maximum number of 
#define RMC_MAX_CONNECTIONS 16


// A an array of connections with its own resource management.
// Used both by rmc_pub_context_t and rmc_sub_context_t.
//
typedef struct rmc_connection_vector {
    // Number of elements in connections.
    uint32_t size;

    // Number of elements in connections that are currently in usebr
    uint32_t connection_count;

    // Top connection index currently in use.
    rmc_connection_index_t max_connection_ind;  

    // Array of connections.
    // Memory provided by rmc_init_connection_vector().
    rmc_connection_t *connections;

    // user data to be provided to poll callbacks.
    user_data_t user_data;

    // When we want to know if a connection can be written to or read from
    rmc_poll_add_cb_t poll_add;

    // We have changed the action bitmap.
    rmc_poll_modify_cb_t poll_modify;
    
    // Callback when we don't need connection ready notifications.
    rmc_poll_remove_cb_t poll_remove;
} rmc_connection_vector_t;


    
// A publisher single context.
typedef struct rmc_pub_context {
    pub_context_t pub_ctx;

    rmc_connection_vector_t conn_vec;

    // Array of subscribers, maintained with the same index as conn_vec
    //
    // 'subscribers' are used when the connection in conn_vec with the
    // same index was accepted by _process_accept() and we take on the
    // role as a publisher of packets.  Added to
    // rmc_pub_context_t::pub_ctx in rmc_init_context() through a
    // pub_init_subscriber() call.  pub_subscriber_t::user_data of the
    // subscriber points to the corresponding conn_vec struct
    pub_subscriber_t *subscribers;

    user_data_t user_data;

    in_addr_t control_listen_if_addr; // In host format for control 
    in_addr_t mcast_group_addr; // In host format
    int mcast_port; // Must be same for all particants.
 
    // Must be different for each process on same machine.
    // Multiple contexts within a single program can share listen port
    // to do load distribution on incoming connections
    int control_listen_port; 

    int mcast_send_descriptor;
    int listen_descriptor;

    
    // Randomly genrated context ID allowing us to recognize and drop
    // looped back multicast messages.
    rmc_context_id_t context_id; 

    // As a publisher, whendo we start re-sending packets via TCP
    // since they weren't acked when we sent them out via multicast
    uint32_t resend_timeout;
    
    // Callback to free memory for packets that has been
    // successfully sent out.
    void (*payload_free)(void* payload,
                         payload_len_t payload_len,
                         user_data_t user_data);


} rmc_pub_context_t;

// A single subscriber context
typedef struct rmc_sub_context {
    sub_context_t sub_ctx;

    rmc_connection_vector_t conn_vec;

    // Array of publishers maintained with the same index as conn_vec
    // 'publishers' are used when we connected to a publisher in _process_multicast_read()
    // as we receive a packet from a previously unknown sender (publisher) that
    // we need to connect a TCP connection to in order to do ack and resend management.
    // Added to rmc_context_t::sub_ctx in rmc_init_context() through a
    // sub_init_publisher() call.
    // sub_publisher_t::user_data of the subscriber points to the corresponding
    // conn_vec struct.
    //
    sub_publisher_t* publishers;

    user_data_t user_data;

    in_addr_t control_address; // Address of control channel
    int control_port; 
    in_addr_t mcast_if_addr; // In host format (little endian)
    in_addr_t mcast_group_addr; // In host format
    int mcast_port; // Must be same for all particants.
 
    // Must be different for each process on same machine.
    // Multiple contexts within a single program can share listen port
    // to do load distribution on incoming connections

    int mcast_recv_descriptor;

    
    // Randomly genrated context ID allowing us to recognize and drop
    // looped back multicast messages.
    rmc_context_id_t context_id; 

    // As a subscriber, how long can we sit on acknowledgements to be
    // sent back to the publisher before we pack them all up
    // and burst them back via tcp.
    uint32_t ack_timeout;

    
    // Called to alloc memory for incoming data.
    // that needs to be processed.
    void* (*payload_alloc)(payload_len_t payload_len,
                               user_data_t user_data);

} rmc_sub_context_t;



// All functions return error codes from error
extern int rmc_pub_init_context(rmc_pub_context_t* context,
                                // Used to avoid loopback dispatch of published packets
                                rmc_context_id_t context_id,
                                // Domain name or IP of multicast group to join.
                                char* multicast_group_addr,  
                                int multicast_port, 

                                // IP address to listen to for incoming subscription
                                // connection from subscribers receiving multicast packets
                                // Default if 0 ptr: "0.0.0.0" (IFADDR_ANY)
                                char* control_listen_iface_addr, 

                                int control_listen_port, 

                                // User data that can be extracted with rmc_user_data(.                            
                                // Typical application is for the poll and memory callbacks below
                                // to tie back to its structure using the provided
                                // pointer to the invoking rmc_context_t structure.
                                user_data_t user_data,

                                // See typedef
                                rmc_poll_add_cb_t poll_add,

                                // See typedef
                                rmc_poll_modify_cb_t poll_modify,

                                // See typedef
                                rmc_poll_remove_cb_t poll_remove,


                                // Byte array of memory to be used for connections and their circular buffers.
                                // Size should be a multiple of sizeof(rmc_connection_t).
                                uint8_t* conn_vec,

                                // Number of elements available in conn_vec.
                                uint32_t conn_vec_size, 

                                // Callback to previously allocated memory provided
                                // by the caller of rmc_queue_packet().
                                //
                                // Invoked by rmc_read() when an ack has been collected
                                // from all subscribers.
                                //
                                // If set 0, free() will be used.
                                void (*payload_free)(void* payload,
                                                     payload_len_t payload_len,
                                                     user_data_t user_data));


// All functions return error codes from error
extern int rmc_sub_init_context(rmc_sub_context_t* context,

                                rmc_context_id_t context_id,

                                // Domain name or IP of multicast group to join.
                                char* multicast_group_addr,  

                                // IP address to listen to for incoming subscription
                                // connection from subscribers receiving multicast packets
                                // Default if 0 ptr: "0.0.0.0" (IFADDR_ANY)
                                char* multicast_iface_addr, 
                                int multicast_port, 

                                // IP address to listen to for incoming subscription
                                // connection from subscribers receiving multicast packets
                                // Default if 0 ptr: "0.0.0.0" (IFADDR_ANY)
                                char* control_addr, 
                                int control_port, 

                                // User data that can be extracted with rmc_user_data(.                            
                                // Typical application is for the poll and memory callbacks below
                                // to tie back to its structure using the provided
                                // pointer to the invoking rmc_context_t structure.
                                user_data_t user_data,


                                // See typedef
                                rmc_poll_add_cb_t poll_add,

                                // See typedef
                                rmc_poll_modify_cb_t poll_modify,

                                // See typedef
                                rmc_poll_remove_cb_t poll_remove,

                                // Byte array of memory to be used for connections and their circular buffers.
                                // Size should be a multiple of sizeof(rmc_connection_t).
                                uint8_t* conn_vec,

                                // Number of elements available in conn_vec.
                                uint32_t conn_vec_size, 

                                // Callback to allocate payload memory used to store
                                // incoming packages. Called via rmc_read() when
                                // a new multicast or tcp payload packet is delivered.
                                //
                                // The allocated memory has to manually freed by the caller
                                // after an rmc_packet_dispatched() has been called to
                                // mark the packet as processed.
                                //
                                // If set to 0, malloc() will be used.
                                void* (*payload_alloc)(payload_len_t payload_len,
                                                       user_data_t user_data));



extern int rmc_pub_activate_context(rmc_pub_context_t* context);
extern int rmc_pub_deactivate_context(rmc_pub_context_t* context);
extern int rmc_pub_set_user_data(rmc_pub_context_t* ctx, user_data_t user_data);
extern user_data_t rmc_pub_user_data(rmc_pub_context_t* ctx);
extern rmc_context_id_t rmc_pub_context_id(rmc_pub_context_t* ctx);
extern int rmc_pub_get_next_timeout(rmc_pub_context_t* context, usec_timestamp_t* result);
extern int rmc_pub_process_timeout(rmc_pub_context_t* context);
extern int rmc_pub_read(rmc_pub_context_t* context, rmc_connection_index_t connection_index, uint8_t* op_res);
extern int rmc_pub_write(rmc_pub_context_t* context, rmc_connection_index_t connection_index, uint8_t* op_res);
extern int rmc_pub_timeout_get_next(rmc_pub_context_t* ctx, usec_timestamp_t* result);
extern int rmc_pub_timeout_process(rmc_pub_context_t* ctx);

extern int rmc_pub_queue_packet(rmc_pub_context_t* context, void* payload, payload_len_t payload_len);


extern int rmc_sub_activate_context(rmc_sub_context_t* context);
extern int rmc_sub_deactivate_context(rmc_sub_context_t* context);
extern int rmc_sub_set_user_data(rmc_sub_context_t* ctx, user_data_t user_data);
extern user_data_t rmc_sub_user_data(rmc_sub_context_t* ctx);
extern rmc_context_id_t rmc_sub_context_id(rmc_sub_context_t* ctx);
extern int rmc_sub_get_next_timeout(rmc_sub_context_t* context, usec_timestamp_t* result);
extern int rmc_sub_process_timeout(rmc_sub_context_t* context);
extern int rmc_sub_read(rmc_sub_context_t* context, rmc_connection_index_t connection_index, uint8_t* op_res);
extern int rmc_sub_write(rmc_sub_context_t* context, rmc_connection_index_t connection_index, uint8_t* op_res);
extern int rmc_sub_timeout_get_next(rmc_sub_context_t* ctx, usec_timestamp_t* result);
extern int rmc_sub_timeout_process(rmc_sub_context_t* ctx);

extern int rmc_sub_get_dispatch_ready_count(rmc_sub_context_t* context);
extern sub_packet_t* rmc_sub_get_next_dispatch_ready(rmc_sub_context_t* context);
extern int rmc_sub_packet_dispatched(rmc_sub_context_t* context, sub_packet_t* packet);

// CALLER STILL HAS TO FREE pack->payload!
extern int rmc_sub_packet_acknowledged(rmc_sub_context_t* context, sub_packet_t* packet);
extern rmc_connection_index_t rmc_sub_packet_connection(sub_packet_t* packet);


// If a valid pointer, res will be set to:

// An error occurred, check return value
#define RMC_ERROR 0

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

// TCP was reset
#define RMC_READ_DISCONNECT 7
 
// Multicast packlet was written
#define RMC_WRITE_MULTICAST 8

// An outbound tcp connection, initated byt rmc_connect_tcp_by_address()
// Was completed.
#define RMC_COMPLETE_CONNECTION 9

// Data was sent on TCP connection.
#define RMC_WRITE_TCP 10


typedef struct rmc_conn_command_dispatch {
    uint8_t command;
    int (*dispatch)(rmc_connection_t* conn, user_data_t user_data);
} rmc_conn_command_dispatch_t;


extern void _rmc_conn_init_connection_vector(rmc_connection_vector_t* conn_vec,
                                             uint8_t* buffer,
                                             uint32_t element_count,
                                             user_data_t user_data,
                                             rmc_poll_add_cb_t poll_add,
                                             rmc_poll_modify_cb_t poll_modify,
                                             rmc_poll_remove_cb_t poll_remove);

extern rmc_connection_t* _rmc_conn_find_by_index(rmc_connection_vector_t* conn_vec,
                                                 rmc_connection_index_t index);

extern rmc_connection_t* _rmc_conn_find_by_address(rmc_connection_vector_t* conn_vec,
                                                   uint32_t remote_address,
                                                   uint16_t remote_port);

extern int _rmc_conn_process_accept(int listen_descriptor,
                                    rmc_connection_vector_t* conn_vec,
                                    rmc_connection_index_t* result_index);

extern int rmc_conn_get_poll_size(rmc_connection_vector_t* conn_vec, int *result);
extern int rmc_conn_get_poll_vector(rmc_connection_vector_t* conn_vec, rmc_connection_t* result, int* len);

extern int _rmc_conn_connect_tcp_by_address(rmc_connection_vector_t* conn_vec,
                                            in_addr_t address,
                                            in_port_t port,
                                            rmc_connection_index_t* result_index);

extern int _rmc_conn_connect_tcp_by_host(rmc_connection_vector_t* conn_vec,
                                         char* server_addr,
                                         in_port_t port,
                                         rmc_connection_index_t* result_index);


extern int _rmc_conn_close_connection(rmc_connection_vector_t* conn_vec,
                                      rmc_connection_index_t s_ind);

extern int _rmc_conn_complete_connection(rmc_connection_vector_t* conn_vec,
                                         rmc_connection_t*conn);

extern int _rmc_conn_process_tcp_write(rmc_connection_t* conn, uint32_t* bytes_left);

extern int _rmc_conn_tcp_read(rmc_connection_vector_t* conn_vec,
                              rmc_connection_index_t s_ind,
                              uint8_t* read_res,
                              rmc_conn_command_dispatch_t* dispatch_table, // Terminated by a null dispatch entry
                              user_data_t user_data);


extern int _rmc_conn_process_tcp_read(rmc_connection_vector_t* conn_vec,
                                      rmc_connection_index_t s_ind,
                                      uint8_t* read_res,
                                      rmc_conn_command_dispatch_t* dispatch_table, // Terminated by a null dispatch entry
                                      user_data_t user_data);
#endif // __RMC_PROTO_H__
