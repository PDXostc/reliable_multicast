// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#ifndef __RELIABLE_MULTICAST_H__
#define __RELIABLE_MULTICAST_H__
#include "rmc_common.h"
#include "circular_buffer.h"
#include "rmc_pub.h"
#include "rmc_sub.h"
#include <netinet/in.h>

#include "rmc_protocol.h"


// Max UDP size is 0xFFE3 (65507). Subtract 0x20 (32) bytes for RMC
// header data.
#define RMC_MAX_PACKET 0xFF78
#define RMC_MAX_PAYLOAD (RMC_MAX_PACKET - sizeof(packet_header_t) - 1)


// Probably needs to be a lot bigger in high
// throughput situations.
#define RMC_MAX_TCP_PENDING_WRITE  // Seems to fit in one tcp segment.
#define RMC_LISTEN_SOCKET_BACKLOG 5

// Number of usecs that publisher will wait after sending
// a packet via UDP multicast before it resends it via TCP
// control channel
#define RMC_DEFAULT_PACKET_TIMEOUT 100000 // 100 msec

// Number of usec a subscriber will wait after receiving
// a packet via UDP multicast before acking it via the
// TCP control channel.
// The reason for the wait is that the subscriber
// wants to collate as many packets as possible
// into as few interval acks as possible.
#define RMC_DEFAULT_ACK_TIMEOUT 50000  // 50 msec

#define RMC_POLLREAD 0x01
#define RMC_POLLWRITE 0x02
#define RMC_MULTICAST_INDEX 0xFFFFFFFE
#define RMC_LISTEN_INDEX 0xFFFFFFFF

#define RMC_CONNECTION_MODE_CLOSED 0
#define RMC_CONNECTION_MODE_CONNECTING 1
#define RMC_CONNECTION_MODE_CONNECTED 2


typedef uint32_t rmc_index_t;
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
                                  rmc_index_t index,
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
                                     rmc_index_t index,
                                     rmc_poll_action_t old_action,
                                     rmc_poll_action_t new_action);



// Callback to remove a connection previously added with poll_add().


typedef void (*rmc_poll_remove_cb_t)(user_data_t user_data,
                                     int descriptor,
                                     rmc_index_t index);

typedef struct rmc_connection {
    // Index of owner rmc_connection_t struct in the master
    // rmc_context_t::connections[] array.
    // rmc_context_t::connections[connection_index].poll_info is this struct.
    // Special cases on RMC_MULTICAST_INDEX and RMC_LISTEN_INDEX
    // to identify the multicast and listen descriptors used
    // by rmc_context_t;x
    rmc_index_t connection_index;

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
    uint8_t read_buf_data[RMC_MAX_PACKET];

    // Circular buffer of pending data read.
    circ_buf_t write_buf;
    uint8_t write_buf_data[RMC_MAX_PACKET]; 

    // RMC_CONNECTION_MODE_CLOSED
    //  The connection is inactive.
    //
    // RMC_CONNECTION_MODE_CONNECTING
    //  The outbound connection is being setup, and we are waiting for
    //  connect() to complete.
    //
    // RMC_CONNECTION_MODE_CONNECTED
    //   The connection is up and running
    //
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
    rmc_index_t max_connection_ind;  

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
    
    // Interval, in usec, in which to send announcement packets that
    // trigger subscribers to connect back to the TCP control socket
    // and setup a subscription.
    // If set to 0, no announcements will be sent out.
    uint32_t announce_send_interval;

    // Next timestamp when we need to send out an announcement
    usec_timestamp_t announce_next_send_ts;

    // Callback invoked every time we are about to send out an announcement.
    // payload is to be filled with the data to send with the announcement.
    // The number of bytes copied into payload cannot be more than
    // max_payload_len.
    // *result_payload_len must be set by the callback to the actual number
    // of bytes copied into payload.
    // If callback_cb is zero, then no payload will be sent out together
    // with the announce packet.
    uint8_t (*announce_cb)(struct rmc_pub_context* ctx,
                           void* payload,
                           payload_len_t max_payload_len,
                           payload_len_t* result_payload_len);

    // Callback invoked every time a subscriber connects to us using
    // a tcp control channel. The connection happens in response to
    // an announce packet being sent out.
    // If this subscriber is to be accepted, the callback shall return 1
    // If this subscriber is to be rejected, the callback shall return 0
    uint8_t (*subscriber_connect_cb)(struct rmc_pub_context* ctx,
                                     char* remote_ip, // "1.2.3.4"
                                     in_port_t remote_port);

    // Callback invoked when a subscriber disconnects.
    void (*subscriber_disconnect_cb)(struct rmc_pub_context* ctx,
                                     char* remote_ip, // "1.2.3.4"
                                     in_port_t remote_port);   // In host format.

    // Callback to free memory for packets that has been
    // successfully sent out. Memory is originally
    // provided as an argument to rmc_pub_queue_packet().
    void (*payload_free)(void* payload,
                         payload_len_t payload_len,
                         user_data_t user_data);


} rmc_pub_context_t;


RMC_LIST(rmc_index_list, rmc_index_node, uint32_t) 
typedef rmc_index_list rmc_index_list_t;
typedef rmc_index_node rmc_index_node_t;

// A single subscriber context
typedef struct rmc_sub_context {
    rmc_connection_vector_t conn_vec;

    // Array of publishers maintained with the same index as conn_vec
    // 'publishers' are used when we connected to a publisher in _process_multicast_read()
    // as we receive a packet from a previously unknown sender (publisher) that
    // we need to connect a TCP connection to in order to do ack and resend management.
    //
    // Added to rmc_context_t::sub_ctx in rmc_init_context() through a
    // sub_init_publisher() call.
    // sub_publisher_t::user_data of the subscriber points to the corresponding
    // conn_vec struct.
    //
    sub_publisher_t* publishers;

    // Packets ready to be dispatched.  These packets are collected
    // from all publishers through calls to
    // sub_process_received_packets().
    sub_packet_list_t dispatch_ready;
    

    // List of indexes of publishers with pending packet acks that are
    // yet to be sent out.  Sorted on ascending pub->oldest_unacked_ts
    // so that we can look at head of list to see which publisher we
    // need to ack next.
    rmc_index_list_t pub_ack_list;

    user_data_t user_data;

    in_addr_t mcast_if_addr; // In host format (little endian)
    in_addr_t mcast_group_addr; // In host format
    int mcast_port; // Must be same for all particants.
 
    // Must be different for each process on same machine.
    // Multiple contexts within a single program can share listen port
    // to do load distribution on incoming connections

    int mcast_recv_descriptor;

    // usec between us receiving a packet and when we have to acknowledge it
    // to the sending publisher via the tcp control channel
    uint32_t ack_timeout; 
    
    // Context ID  allowing us to recognize and drop
    // looped back multicast messages.
    // Provided to rmc_sub_init_context() or generated to random number.
    rmc_context_id_t context_id; 

    // Callback invoked every time we receive an announce packet
    // from an unsubscribed-to publisher. 
    //
    // Payload is the payload provided to the announce packet by a
    // callback to the publishers side's pub_context_t::annouce_cb()
    // callback.
    //
    // Listen ip and port is the end point of the tcp control channel to
    // that the publisher accepts subscription connections to.
    // This is the address that will be connected to by subscriber
    // if announce_cb returns non-zero. (See below).
    //
    // If announce_cb returns a non-zero value, then a subscription will
    // be setup to the publisher that sent the announce packet.
    // If announce_cb returns 0 no subscription will be setup, and
    // announce_cb will be invoked again the next time an announce packet
    // is received from the same publisher.
    //
    // If announce_cb is not set then the subscription will always be setup.
    uint8_t (*announce_cb)(struct rmc_sub_context* ctx,
                           char* listen_ip, // "1.2.3.4"
                           in_port_t listen_port,
                           void* payload,
                           payload_len_t payload_len);

    // Called to alloc memory for incoming data.
    // that needs to be processed.
    void* (*payload_alloc)(payload_len_t payload_len,
                           user_data_t user_data);

    // Called to free memory previously allocated with
    // payload_alloc().
    // If 0, free() will be used.
    void (*payload_free)(void* payload,
                         payload_len_t payload_len,
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
                                // The allocated memory will be automnatically freed
                                // via a payload_free callback (see below) when
                                // the packet has been acknowledged via a call
                                // to rmc_sub_timeout_process() call.
                                //
                                // user_data will be set to the same user_data as provided
                                // to rmc_sub_init_context().
                                //
                                // If set to 0, malloc() will be used.
                                void* (*payload_alloc)(payload_len_t payload_len,
                                                       user_data_t user_data),

                                // Callback to free memory previously allocated via
                                // the payload_alloc callback.
                                // The payload_free is called via rmc_sub_timeout_process()
                                // when it has queued up the tcp command to acknowledge a packet
                                // in rmc_sub_packet_acknowledged().
                                //
                                // user_data will be set to the same user_data as provided
                                // to rmc_sub_init_context().
                                //
                                // If set to 0, free() will be used.
                                void (*payload_free)(void* payload,
                                                     payload_len_t payload_len,
                                                     user_data_t user_data));




extern int rmc_pub_activate_context(rmc_pub_context_t* context);
extern int rmc_pub_set_announce_interval(rmc_pub_context_t* context, uint32_t send_interval_usec);
extern int rmc_pub_set_announce_callback(rmc_pub_context_t* context,
                                         uint8_t (*announce_cb)(struct rmc_pub_context* ctx,
                                                                void* payload,
                                                                payload_len_t max_payload_len,
                                                                payload_len_t* result_payload_len));

// Set callback to be invoked when subscriber connects.
// Return 1 if connection is allowed. 0 if rejected.
// If callback is set to 0 (default) all incoming connections will be accepted.,
extern int rmc_pub_set_subscriber_connect_callback(rmc_pub_context_t* ctx,
                                                   uint8_t (*connect_cb)(struct rmc_pub_context* ctx,
                                                                             char* remote_ip, // "1.2.3.4"
                                                                             in_port_t remote_port));

// Set callback to be invoked when subscriber disconnects.
// Return 1 if connection is allowed. 0 if rejected.
// If callback is set to 0 (default) all incoming connections will be accepted.,
extern int rmc_pub_set_subscriber_disconnect_callback(rmc_pub_context_t* ctx,
                                                      void (*disconnect_cb)(struct rmc_pub_context* ctx,
                                                                            char* remote_ip, // "1.2.3.4"
                                                                            in_port_t remote_port));

extern int rmc_pub_deactivate_context(rmc_pub_context_t* context);
extern int rmc_pub_set_user_data(rmc_pub_context_t* ctx, user_data_t user_data);
extern user_data_t rmc_pub_user_data(rmc_pub_context_t* ctx);
extern rmc_context_id_t rmc_pub_context_id(rmc_pub_context_t* ctx);
extern int rmc_pub_get_next_timeout(rmc_pub_context_t* context, usec_timestamp_t* result);
extern int rmc_pub_process_timeout(rmc_pub_context_t* context);
extern int rmc_pub_read(rmc_pub_context_t* context, rmc_index_t connection_index, uint8_t* op_res);
extern int rmc_pub_write(rmc_pub_context_t* context, rmc_index_t connection_index, uint8_t* op_res);
extern int rmc_pub_close_connection(rmc_pub_context_t* ctx, rmc_index_t s_ind);

extern int rmc_pub_timeout_get_next(rmc_pub_context_t* ctx, usec_timestamp_t* result);
extern int rmc_pub_timeout_process(rmc_pub_context_t* ctx);

extern int rmc_pub_queue_packet(rmc_pub_context_t* ctx,
                                void* payload,
                                payload_len_t payload_len,
                                uint8_t announce_flag);

extern int rmc_pub_packet_ack(rmc_pub_context_t* ctx, rmc_connection_t* conn, packet_id_t pid);

// Get stats on what is pending to be sent out.
//
// queued_packets is the number of packets we have not yet sent.
//
// send_buf_len is the sum of the number of bytes we have put on all
// tcp channel that remain to be sent.
//
// ack_count is the number of packets we have sent that we have yet
// to receive an ack on (and therefore may have to resend).
//
extern int rmc_pub_context_get_pending(rmc_pub_context_t* ctx,
                                       uint32_t* queued_packets, 
                                       uint32_t* send_buf_len,
                                       uint32_t* ack_count);


extern int rmc_sub_activate_context(rmc_sub_context_t* context);
extern int rmc_sub_deactivate_context(rmc_sub_context_t* context);

extern int rmc_sub_close_connection(rmc_sub_context_t* ctx, rmc_index_t s_ind);

extern int rmc_sub_set_announce_callback(rmc_sub_context_t* context,
                                         uint8_t (*announce_cb)(struct rmc_sub_context* ctx,
                                                                char* listen_ip, // "1.2.3.4"
                                                                in_port_t listen_port,
                                                                void* payload,
                                                                payload_len_t payload_len));


extern int rmc_sub_set_user_data(rmc_sub_context_t* ctx, user_data_t user_data);
extern user_data_t rmc_sub_user_data(rmc_sub_context_t* ctx);
extern rmc_context_id_t rmc_sub_context_id(rmc_sub_context_t* ctx);

extern int rmc_sub_packet_received(rmc_sub_context_t* ctx,
                                   rmc_index_t index, 
                                   packet_id_t pid,
                                   void* payload,
                                   payload_len_t payload_len,
                                   usec_timestamp_t current_ts,
                                   user_data_t pkg_user_data);
extern int rmc_sub_get_next_timeout(rmc_sub_context_t* context, usec_timestamp_t* result);
extern int rmc_sub_process_timeout(rmc_sub_context_t* context);
extern int rmc_sub_read(rmc_sub_context_t* context, rmc_index_t connection_index, uint8_t* op_res);
extern int _rmc_sub_write_single_acknowledgement(rmc_sub_context_t* ctx,
                                                 rmc_connection_t* conn,
                                                 packet_id_t);
extern int rmc_sub_write(rmc_sub_context_t* context, rmc_index_t connection_index, uint8_t* op_res);
extern int rmc_sub_timeout_get_next(rmc_sub_context_t* ctx, usec_timestamp_t* result);
extern int rmc_sub_timeout_process(rmc_sub_context_t* ctx);

extern int rmc_sub_get_dispatch_ready_count(rmc_sub_context_t* context);
extern sub_packet_t* rmc_sub_get_next_dispatch_ready(rmc_sub_context_t* context);
extern int rmc_sub_packet_dispatched(rmc_sub_context_t* context, sub_packet_t* packet);

extern int _rmc_sub_single_packet_acknowledged(rmc_sub_context_t* context, sub_packet_t* packet);
extern int _rmc_sub_write_interval_acknowledgement(rmc_sub_context_t* ctx,
                                                   rmc_connection_t* conn,
                                                   sub_pid_interval_t* interval);

extern int rmc_sub_packet_interval_acknowledged(rmc_sub_context_t* context,
                                                rmc_index_t index,
                                                sub_pid_interval_t* interval);

extern rmc_index_t rmc_sub_packet_connection(sub_packet_t* packet);


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


extern void rmc_conn_init_connection_vector(rmc_connection_vector_t* conn_vec,
                                            uint8_t* buffer,
                                            uint32_t element_count,
                                            user_data_t user_data,
                                            rmc_poll_add_cb_t poll_add,
                                            rmc_poll_modify_cb_t poll_modify,
                                            rmc_poll_remove_cb_t poll_remove);

extern rmc_connection_t* rmc_conn_find_by_index(rmc_connection_vector_t* conn_vec,
                                                rmc_index_t index);

extern rmc_connection_t* rmc_conn_find_by_address(rmc_connection_vector_t* conn_vec,
                                                  uint32_t remote_address,
                                                  uint16_t remote_port);

extern int rmc_conn_process_accept(int listen_descriptor,
                                   rmc_connection_vector_t* conn_vec,
                                   rmc_index_t* result_index);

extern int rmc_conn_get_pending_send_length(rmc_connection_t* conn, payload_len_t* result);
extern int rmc_conn_get_max_index_in_use(rmc_connection_vector_t* conn_vec, rmc_index_t *result);
extern int rmc_conn_get_poll_size(rmc_connection_vector_t* conn_vec, int *result);
extern int rmc_conn_get_poll_vector(rmc_connection_vector_t* conn_vec, rmc_connection_t* result, int* len);

extern int rmc_conn_connect_tcp_by_address(rmc_connection_vector_t* conn_vec,
                                           in_addr_t address,
                                           in_port_t port,
                                           rmc_index_t* result_index);

extern int rmc_conn_connect_tcp_by_host(rmc_connection_vector_t* conn_vec,
                                        char* server_addr,
                                        in_port_t port,
                                        rmc_index_t* result_index);



extern int rmc_conn_close_connection(rmc_connection_vector_t* conn_vec,
                                     rmc_index_t s_ind);

extern int rmc_conn_complete_connection(rmc_connection_vector_t* conn_vec,
                                        rmc_connection_t*conn);

extern int rmc_conn_process_tcp_write(rmc_connection_t* conn, uint32_t* bytes_left);

extern int rmc_pub_resend_packet(rmc_pub_context_t* ctx,
                                 rmc_connection_t* conn,
                                  pub_packet_t* pack);

extern int rmc_conn_tcp_read(rmc_connection_vector_t* conn_vec,
                             rmc_index_t s_ind,
                             uint8_t* read_res,
                             rmc_conn_command_dispatch_t* dispatch_table, // Terminated by a null dispatch entry
                             user_data_t user_data);


extern int rmc_conn_process_tcp_read(rmc_connection_vector_t* conn_vec,
                                     rmc_index_t s_ind,
                                     uint8_t* read_res,
                                     rmc_conn_command_dispatch_t* dispatch_table, // Terminated by a null dispatch entry
                                     user_data_t user_data);
#endif // __RELIABLE_MULTICAST_H__
