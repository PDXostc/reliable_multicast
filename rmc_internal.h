// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#ifndef __RMC_INTERNAL_H__
#define __RMC_INTERNAL_H__
#include "reliable_multicast.h"
#include "circular_buffer.h"
#include "rmc_pub.h"
#include "rmc_sub.h"
#include <netinet/in.h>

#include "rmc_protocol.h"

RMC_LIST(packet_id_list, packet_id_node, packet_id_t)
typedef packet_id_list packet_id_list_t;
typedef packet_id_node packet_id_node_t;

RMC_LIST(rmc_index_list, rmc_index_node, rmc_index_t)
typedef rmc_index_list rmc_index_list_t;
typedef rmc_index_node rmc_index_node_t;

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

#define RMC_NIL_INDEX 0x7FFF
#define RMC_MULTICAST_INDEX 0x7FFE
#define RMC_LISTEN_INDEX 0x7FFD

#define RMC_CONNECTION_MODE_CLOSED 0
#define RMC_CONNECTION_MODE_CONNECTING 1
#define RMC_CONNECTION_MODE_CONNECTED 2



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

    // Node ID of publisher that a subscriber connected to.
    // Derived from node ID of announce packet sent out by publisher
    // that triggered subscriber to connect back to it.
    // This field is unused by publisher-side and will remeain 0.
    rmc_node_id_t node_id;

    // Circular buffer of pending data read.
    circ_buf_t read_buf;

    // backing buffer for circ_buf above.  circ_buf_data and circ_buf
    // are tied toegther through the circ_buf_init() call.
    // One byte extra needed by circ buf for housekeeping reasons.
    // FIXME: Use shared circular buffer across all rmc_connections for both read and write.
    //        Right now we allocate 128K of ram even if the rmc_connection_t struct is not
    //        in use (nobody connected), or if there are currently no buffered data.
    //        At the very least allocate memory only for rmc_connections that are
    //        actually connected
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


// A an array of connections with its own resource management.
// Used both by rmc_pub_context_t and rmc_sub_context_t.
//
typedef struct rmc_connection_vector {
    // Number of elements in connections.
    rmc_index_t size;

    // Max connection index currently in use.
    rmc_index_t max_connection_ind;

    // Number of connections currently in use
    rmc_index_t active_connection_count;

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
    in_addr_t mcast_if_addr; // In host format (little endian)
    in_addr_t mcast_group_addr; // In host format
    int mcast_port; // Must be same for all particants.

    // Must be different for each process on same machine.
    // Multiple contexts within a single program can share listen port
    // to do load distribution on incoming connections
    int control_listen_port;

    int mcast_send_descriptor;
    int listen_descriptor;


    // Node ID allowing us to recognize and drop looped back multicast messages.
    // Also allow subscribing parties to uniquely identify this publisher..
    // Set by rmc_pub_init_context(), or generated randonly if set to 0.
    rmc_node_id_t node_id;

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


    // At how manu inflight packets do we suspend rmc_pub_queue_packet() from accepting
    // more packets.
    // Once stopped the inflight count needs to go below traffic_resume_threshold
    // before rmc_pub_queue_packet() starts accepting packets again.
    // If either are 0, traffic throttling is disabled.
    uint32_t traffic_suspend_threshold;
    uint32_t traffic_resume_threshold;

    // Set to 1 if traffic has been suspended by an inflight_count_suspend_traffic
    // threshold breach. Will be cleared once inflight count goes under
    // inflight_count_resume_traffic.
    uint8_t traffic_suspended;

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
                                     uint32_t remote_ip, // In host format
                                     in_port_t remote_port);

    // Callback invoked when a subscriber disconnects.
    void (*subscriber_disconnect_cb)(struct rmc_pub_context* ctx,
                                     uint32_t remote_ip,  // In host format
                                     in_port_t remote_port);   // In host format.

    // Callback invoked when a control message is received from the subscriber.
    // Subscriber sends the message using  rmc_sub_write_control_message_by_address() or
    //  rmc_sub_write_control_message_by_node_id()
    void (*subscriber_control_message_cb)(struct rmc_pub_context* ctx,
                                          uint32_t publisher_address,
                                          uint16_t publisher_port,
                                          rmc_node_id_t node_id,
                                          void* payload,
                                          payload_len_t payload_len);

    // Callback to free memory for packets that has been
    // successfully sent out. Memory is originally
    // provided as an argument to rmc_pub_queue_packet().
    void (*payload_free)(void* payload,
                         payload_len_t payload_len,
                         user_data_t user_data);


} rmc_pub_context_t;

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

    // Node ID allowing us to recognize and drop looped back multicast messages.
    // Also allow publishing parties to uniquely identify this publisher.
    // Set by rmc_pub_init_context(), or generated randonly if set to 0.
    rmc_node_id_t node_id;

    // Callback invoked when one or more packets become available for dispatch.
    // Use rmc_sub_get_next_dispatch_ready() to retrieve the packet for processing.
    // Use rmc_sub_packet_dispatched() to mark the packet as processed.
    // Repeat until rmc_sub_get_next_dispatch_ready() return NULL.
    void (*packet_ready_cb)(struct rmc_sub_context* ctx);

    // Callback invoked every time we receive an announce packet
    // from an unsubscribed-to publisher.
    //
    // Payload is the payload provided to the announce packet by a
    // callback to the publishers side's pub_context_t::annouce_cb()
    // callback.
    //
    // Listen ip and port is the end point of the tcp control channel to
    // that the publisher accepts subscription connections to.
    //
    // Convert the IP address to an aaa.bbb.ccc.ddd IP address using the following
    // statement:
    //
    //    inet_ntoa( (struct in_addr) { .s_addr = htonl( listen_ip) })
    //
    // node_id is the ID setup by the publisher when rmc_pub_init_context() was called
    //
    // If announce_cb returns a non-zero value, then a subscription will
    // be setup to the publisher that sent the announce packet.
    // If announce_cb returns 0 no subscription will be setup, and
    // announce_cb will be invoked again the next time an announce packet
    // is received from the same publisher.
    //
    // If announce_cb is not setup using rmc_sub_set_announce_callback(),
    // then the subscription will always be setup.
    uint8_t (*announce_cb)(struct rmc_sub_context* ctx,
                           uint32_t listen_ip,
                           in_port_t listen_port,
                           rmc_node_id_t node_id,
                           void* payload,
                           payload_len_t payload_len);

    // Callback invoked every time we have setup a tcp control
    // channel to a publisher, thereby activating a subscrtiption./
    //
    // This call will be invoked once the announce_cb callback above
    // has returned 1,
    //
    // Listen ip and port is the end point of the tcp control channel to
    // that the publisher accepts subscription connections to.
    //
    // Convert the IP address to an aaa.bbb.ccc.ddd IP address using the following
    // statement:
    //
    //    inet_ntoa( (struct in_addr) { .s_addr = htonl( listen_ip) })
    //
    // node_id is the ID setup by the publisher when rmc_pub_init_context() was called
    //
    // If subscription_complete_cb is not setup using rmc_sub_set_subscribe_callback(),
    // then no notification will be issued about a successful connection.
    void (*subscription_complete_cb)(struct rmc_sub_context* ctx,
                                     uint32_t listen_ip,
                                     in_port_t listen_port,
                                     rmc_node_id_t node_id);

    // FIXME: We need an unsubsribe callback to be invoked when a connection
    //        to a publisher has been shut down.

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

typedef struct rmc_conn_command_dispatch {
    uint8_t command;
    int (*dispatch)(struct rmc_connection* conn, user_data_t user_data);
} rmc_conn_command_dispatch_t;



extern int rmc_pub_packet_ack(struct rmc_pub_context* ctx, struct rmc_connection* conn, packet_id_t pid);





extern int _rmc_sub_write_single_acknowledgement(struct rmc_sub_context* ctx,
                                                 struct rmc_connection* conn,
                                                 packet_id_t);


extern int _rmc_sub_write_single_acknowledgement(struct rmc_sub_context* ctx,
                                                 struct rmc_connection* conn,
                                                 packet_id_t);

extern int rmc_sub_write_interval_acknowledgement(struct rmc_sub_context* ctx,
                                                  struct rmc_connection* conn,
                                                  sub_pid_interval_t* interval);



extern int rmc_sub_packet_interval_acknowledged(struct rmc_sub_context* context,
                                                rmc_index_t index,
                                                sub_pid_interval_t* interval);

extern rmc_index_t rmc_sub_packet_connection(sub_packet_t* packet);

extern void rmc_conn_init_connection_vector(struct rmc_connection_vector* conn_vec,
                                            uint8_t* buffer,
                                            uint32_t element_count,
                                            user_data_t user_data,
                                            rmc_poll_add_cb_t poll_add,
                                            rmc_poll_modify_cb_t poll_modify,
                                            rmc_poll_remove_cb_t poll_remove);

extern struct rmc_connection* rmc_conn_find_by_index(struct rmc_connection_vector* conn_vec,
                                                     rmc_index_t index);

extern struct rmc_connection* rmc_conn_find_by_address(struct rmc_connection_vector* conn_vec,
                                                       uint32_t remote_address,
                                                       uint16_t remote_port);

extern struct rmc_connection* rmc_conn_find_by_node_id(struct rmc_connection_vector* conn_vec,
                                                       rmc_node_id_t node_id);

extern int rmc_conn_process_accept(int listen_descriptor,
                                   struct rmc_connection_vector* conn_vec,
                                   rmc_index_t* result_index);


extern int rmc_conn_connect_tcp_by_address(struct rmc_connection_vector* conn_vec,
                                           in_addr_t address,
                                           in_port_t port,
                                           rmc_node_id_t node_id,
                                           rmc_index_t* result_index);


extern int rmc_conn_close_connection(struct rmc_connection_vector* conn_vec,
                                     rmc_index_t s_ind);

extern int rmc_conn_complete_connection(struct rmc_connection_vector* conn_vec,
                                        struct rmc_connection*conn);

extern int rmc_conn_process_tcp_write(struct rmc_connection* conn, uint32_t* bytes_left);

extern int rmc_pub_resend_packet(struct rmc_pub_context* ctx,
                                 struct rmc_connection* conn,
                                 pub_packet_t* pack);

extern int rmc_conn_tcp_read(struct rmc_connection_vector* conn_vec,
                             rmc_index_t s_ind,
                             uint8_t* read_res,
                             rmc_conn_command_dispatch_t* dispatch_table, // Terminated by a null dispatch entry
                             user_data_t user_data);


extern int rmc_conn_process_tcp_read(struct rmc_connection_vector* conn_vec,
                                     rmc_index_t s_ind,
                                     uint8_t* read_res,
                                     rmc_conn_command_dispatch_t* dispatch_table, // Terminated by a null dispatch entry
                                     user_data_t user_data);




extern int rmc_conn_get_pending_send_length(struct rmc_connection* conn, payload_len_t* result);
extern int rmc_conn_get_active_connection_count(struct rmc_connection_vector* conn_vec, rmc_index_t *result);


extern int rmc_conn_get_max_index_in_use(struct rmc_connection_vector* conn_vec, rmc_index_t *result);
extern int rmc_conn_get_vector_size(struct rmc_connection_vector* conn_vec, rmc_index_t *result);

#endif // __RMC_INTERNAL_H__
