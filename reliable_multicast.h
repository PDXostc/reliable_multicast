// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#ifndef __RELIABLE_MULTICAST_H__
#define __RELIABLE_MULTICAST_H__
#include <stdint.h>
#include <netinet/in.h>
#include "rmc_list.h"

typedef uint64_t packet_id_t;
typedef uint32_t rmc_node_id_t;

typedef uint16_t payload_len_t;
typedef int64_t usec_timestamp_t;

typedef union {
    void* ptr;
    uint32_t u32;
    int32_t i32;
    uint64_t u64;
    int64_t i64;
} user_data_t;

#define user_data_nil() ((user_data_t) { .u64 = 0 })
#define user_data_u64(_u64) ((user_data_t) { .u64 = _u64 })
#define user_data_i64(_i64) ((user_data_t) { .i64 = _i64 })
#define user_data_u32(_u32) ((user_data_t) { .u32 = _u32 })
#define user_data_i32(_i32) ((user_data_t) { .i32 = _i32 })
#define user_data_ptr(_ptr) ((user_data_t) { .ptr = _ptr })

// Used for iterators etc.
#define lambda(return_type, function_body) \
    ({                                     \
        return_type __fn__ function_body   \
            __fn__;                        \
    })


extern usec_timestamp_t rmc_usec_monotonic_timestamp(void);

typedef uint16_t rmc_index_t;
typedef uint16_t rmc_poll_action_t;

// Max UDP size is 0xFFE3 (65507).
// Max TCP segment that seems to fit comfortably is 0xFF78.
// Subtract some headers to get max payload
#define RMC_MAX_PACKET 0xFF78
#define RMC_MAX_PAYLOAD 0xFF20

#define RMC_POLLREAD 0x01
#define RMC_POLLWRITE 0x02

// Called when a new connection is created by rmc.
//
// poll->action & RMC_POLLREAD specifies that we want rmc_write() to
// be called (with poll->connection_index as an argument) when the
// connection can be written to (asynchronously).
//
// poll->action & RMC_POLLWRITE specifies that we want rmc_write() to
// be called (with poll->connection_index as an argument) when the
// connection can be written to (asynchronously).
//
typedef void (*rmc_poll_add_cb_t)(user_data_t user_data,
                                  int descriptor,
                                  rmc_index_t index,
                                  rmc_poll_action_t initial_action);

// The poll action either needs to be re-armed in cases where polling
// is oneshot (epoll(2) with EPOLLONESHOT), or the poll action has
// changed.
//
// Rearming can be detected by checking if old_action ==
// rmc_connection_action(sock);
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

// An RMC connection to a remote node
struct rmc_connection;

// A an array of connections with its own resource management.
// Used both by rmc_pub_context_t and rmc_sub_context_t.
//
struct rmc_pub_context;
typedef struct rmc_pub_context rmc_pub_context_t;

struct rmc_sub_context;
typedef struct rmc_sub_context rmc_sub_context_t;

struct sub_packet;
typedef struct sub_packet rmc_sub_packet_t;

// All functions return error codes from error
extern int rmc_pub_init_context(struct rmc_pub_context** context,
                                // Used to avoid loopback dispatch of published packets
                                rmc_node_id_t node_id,
                                // Domain name or IP of multicast group to join.
                                char* multicast_group_addr,
                                int multicast_port,
                                // IP address to listen to for incoming subscription
                                // connection from subscribers receiving multicast packets
                                // Default if 0 ptr: "0.0.0.0" (IFADDR_ANY)
                                char* multicast_iface_addr,

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


                                // Maximum number of publishers we
                                // expect.  Please note that each
                                // publisher, active or not, consumes
                                // 64K of ram.
                                uint32_t max_publishers,

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
extern int rmc_sub_init_context(struct rmc_sub_context** context,

                                rmc_node_id_t node_id,

                                // Domain name or IP of multicast group to join.
                                char* multicast_group_addr,

                                int multicast_port,
                                // IP address to listen to for incoming subscription
                                // connection from subscribers receiving multicast packets
                                // Default if 0 ptr: "0.0.0.0" (IFADDR_ANY)
                                char* multicast_iface_addr,

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


                                // Maximum number of publishers we
                                // expect.  Please note that each
                                // publisher, active or not, consumes
                                // 64K of ram.
                                uint32_t max_publishers,

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




extern int rmc_pub_activate_context(struct rmc_pub_context* context);
extern int rmc_pub_set_announce_interval(struct rmc_pub_context* context, uint32_t send_interval_usec);
extern int rmc_pub_set_announce_callback(struct rmc_pub_context* context,
                                         uint8_t (*announce_cb)(struct rmc_pub_context* ctx,
                                                                void* payload,
                                                                payload_len_t max_payload_len,
                                                                payload_len_t* result_payload_len));


// Set callback to be invoked when subscriber connects.
// Return 1 if connection is allowed. 0 if rejected.
// If callback is set to 0 (default) all incoming connections will be accepted.,
extern int rmc_pub_set_subscriber_connect_callback(struct rmc_pub_context* ctx,
                                                   uint8_t (*connect_cb)(struct rmc_pub_context* ctx,
                                                                         uint32_t remote_ip,
                                                                         in_port_t remote_port));

// Set callback to be invoked when subscriber disconnects.
// Return 1 if connection is allowed. 0 if rejected.
// If callback is set to 0 (default) all incoming connections will be accepted.,
extern int rmc_pub_set_subscriber_disconnect_callback(struct rmc_pub_context* ctx,
                                                      void (*disconnect_cb)(struct rmc_pub_context* ctx,
                                                                            uint32_t remote_ip,
                                                                            in_port_t remote_port));


// Set the callback to be invoked when a control message is received from a subscriber.
// Subscriber sends the message using  rmc_sub_write_control_message_by_address() or
//  rmc_sub_write_control_message_by_node_id()
extern int rmc_pub_set_control_message_callback(struct rmc_pub_context* context,
                                                void (*control_message_cb)(struct rmc_pub_context* ctx,
                                                                           uint32_t publisher_address,
                                                                           uint16_t publisher_port,
                                                                           rmc_node_id_t node_id,
                                                                           void* payload,
                                                                           payload_len_t payload_len));

extern int rmc_pub_deactivate_context(struct rmc_pub_context* context);
extern int rmc_pub_delete_context(struct rmc_pub_context* context);
extern int rmc_pub_set_multicast_ttl(struct rmc_pub_context* ctx, int hops);
extern int rmc_pub_set_user_data(struct rmc_pub_context* ctx, user_data_t user_data);
extern int rmc_pub_throttling(struct rmc_pub_context* ctx, uint32_t suspend_threshold, uint32_t resume_threhold);
extern int rmc_pub_traffic_suspended(struct rmc_pub_context* ctx);
extern user_data_t rmc_pub_user_data(struct rmc_pub_context* ctx);
extern rmc_node_id_t rmc_pub_node_id(struct rmc_pub_context* ctx);
extern int rmc_pub_close_connection(struct rmc_pub_context* ctx, rmc_index_t s_ind);

extern int rmc_pub_timeout_get_next(struct rmc_pub_context* ctx, usec_timestamp_t* result);
extern int rmc_pub_timeout_process(struct rmc_pub_context* ctx);

extern int rmc_pub_queue_packet(struct rmc_pub_context* ctx,
                                void* payload,
                                payload_len_t payload_len,
                                uint8_t announce_flag);

extern uint32_t rmc_pub_queue_length(struct rmc_pub_context* ctx);
extern rmc_index_t rmc_pub_get_max_subscriber_count(struct rmc_pub_context* ctx);
extern uint32_t rmc_pub_get_subscriber_count(struct rmc_pub_context* ctx);
extern uint32_t rmc_pub_get_socket_count(struct rmc_pub_context* ctx);

extern int rmc_sub_read(struct rmc_sub_context* context, rmc_index_t connection_index, uint8_t* op_res);
extern int rmc_sub_write(struct rmc_sub_context* context, rmc_index_t connection_index, uint8_t* op_res);
extern int rmc_pub_read(struct rmc_pub_context* context, rmc_index_t connection_index, uint8_t* op_res);
extern int rmc_pub_write(struct rmc_pub_context* context, rmc_index_t connection_index, uint8_t* op_res);

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
extern int rmc_pub_context_get_pending(struct rmc_pub_context* ctx,
                                       uint32_t* queued_packets,
                                       uint32_t* send_buf_len,
                                       uint32_t* ack_count);



extern int rmc_sub_activate_context(struct rmc_sub_context* context);
extern int rmc_sub_deactivate_context(struct rmc_sub_context* context);
extern int rmc_sub_delete_context(struct rmc_sub_context* context);

extern int rmc_sub_close_connection(struct rmc_sub_context* ctx, rmc_index_t s_ind);

extern int rmc_sub_set_subscription_complete_callback(struct rmc_sub_context* context,
                                                      void (*subscription_complete_cb)
                                                      (struct rmc_sub_context* ctx,
                                                       uint32_t listen_ip,
                                                       in_port_t listen_port,
                                                       rmc_node_id_t node_id));

extern int rmc_sub_set_announce_callback(struct rmc_sub_context* context,
                                         uint8_t (*announce_cb)
                                         (struct rmc_sub_context* ctx,
                                          uint32_t listen_ip,
                                          in_port_t listen_port,
                                          rmc_node_id_t node_id,
                                          void* payload,
                                          payload_len_t payload_len));

// Set callback to be invoked when a packet becomes available for processing using
// rmc_sub_get_next_dispatch_ready() and rmc_sub_packet_dispatched() calls.
extern int rmc_sub_set_packet_ready_callback(struct rmc_sub_context* context,
                                             void (*packet_ready_cb)(struct rmc_sub_context* ctx));


extern int rmc_sub_set_user_data(struct rmc_sub_context* ctx, user_data_t user_data);
extern user_data_t rmc_sub_user_data(struct rmc_sub_context* ctx);
extern rmc_node_id_t rmc_sub_node_id(struct rmc_sub_context* ctx);

// Queue a control message, sent via the tcp control channel, to the
// publisher.
//
// Message will be delivered to publisher via the callbac sketup by
// rmc_pub_set_control_message_callback().
//
// If callback has not been set, then control message will be dropped
// by publisher.
//
// publisher_node_id will have been provided through a prior to
// the callback specified by rmc_sub_set_announce_callback() when
// the subscription was originally setup.
//
extern int rmc_sub_write_control_message_by_node_id(struct rmc_sub_context* ctx,
                                                    rmc_node_id_t publisher_node_id,
                                                    void* payload,
                                                    payload_len_t payload_len);

// publisher_address and publisher_port will have been provided through a prior to
// the callback specified by rmc_sub_set_announce_callback() when
// the subscription was originally setup.
//
extern int rmc_sub_write_control_message_by_address(struct rmc_sub_context* ctx,
                                                    uint32_t publisher_address,
                                                    uint16_t publisher_port,
                                                    void* payload,
                                                    payload_len_t payload_len);

extern int rmc_sub_packet_received(struct rmc_sub_context* ctx,
                                   rmc_index_t index,
                                   packet_id_t pid,
                                   void* payload,
                                   payload_len_t payload_len,
                                   usec_timestamp_t current_ts,
                                   user_data_t pkg_user_data);

extern int rmc_sub_process_timeout(struct rmc_sub_context* context);
extern int rmc_sub_timeout_get_next(struct rmc_sub_context* ctx, usec_timestamp_t* result);
extern int rmc_sub_timeout_process(struct rmc_sub_context* ctx);

extern int rmc_sub_get_dispatch_ready_count(struct rmc_sub_context* context);
extern struct sub_packet* rmc_sub_get_next_dispatch_ready(struct rmc_sub_context* context);
extern int rmc_sub_packet_dispatched(struct rmc_sub_context* context, struct sub_packet* packet);
extern rmc_index_t rmc_sub_get_max_publisher_count(struct rmc_sub_context* ctx);
extern rmc_index_t rmc_sub_get_publisher_count(struct rmc_sub_context* ctx);
extern uint32_t rmc_sub_get_socket_count(struct rmc_sub_context* ctx);
extern void* rmc_sub_packet_payload(struct sub_packet* pack);
extern payload_len_t rmc_sub_packet_payload_len(struct sub_packet* pack);


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

#endif // __RELIABLE_MULTICAST_H__
