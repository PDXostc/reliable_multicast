# RELIABLE MULTICAST [RMC] - PROTOCOL SPECIFICATION

RMC uses a combination of UDP Multicast and TCP control
channel connections to handle bulk data transmission,
acknowledgements, and resends. The system is setup as one or more
publishers sending packets received by one or more subscribers, as
shown below.

![Network Topology](./images/rmc_fig1.png?raw=true)

Unlinke TCP-based protocols that have to send the same data
individually to each subscriber, RMC can add additional subscribers
with a minimum of overhead.

# TERMINOLOGY

Term                   | Description
-----------------------|------------
Node ID                | A unique, per-process ID, that identifies publishers and subscribers.
Control channel        | A TCP connection setup from the subscriber to the publisher to acknowledge packets and do resends.
Multicast Address:Port | The channel onto which one or more publishers can send data to be received by subscribers.



# OPERATIONS OVERVIEW
The following chapters describe the sequence for connecting a
publisher to a subscriber and transmitting packets between them.

## Announce - Connect

The announce-connect sequence allows publishers to make their
availability known to subscribrers, and subscribers to connect to the
publisher in order to receive published packets.

![Connect Sequence](./images/rmc_fig2.png?raw=true)

A subscriber who wants to receive published packets starts by adding
itself as a member of a predefined multicast UDP/IP group using
standard POSIX network APIs.

A publisher can announce its availability to the network by sending
out announce packets to the given multicast group. The announce packet
contains information about the publisher's Node ID, and the TCP address and
port of the publisher's control channel.

The subscriber responds to a received announce packet by setting up a
TCP connection to the control channel address provided in the
packet. The source address:port tuple of the subscriber will be used
by the publisher to identify the subscriber.

The establishment of a control channel connection from a subscriber to
a publisher is all that is needed for a subscription to become active.
The subscription stays active until the connection is broken either by
the subscriber or the publisher.

Please note that a subscriber is free to connect to a publisher
without having received an announce packet. If the subscriber knows
the IP address and port of the publisher, via config file or similar
mechanism, it can directly connect to the publisher's control channel
in order to establish a publisher-subcriber relationship.

## Packet Publishing

The publisher can at any time send out UDP Multicast packets for
subscribers to pick up. Subscribers will then use the control channel
to acknowledge sequences of successfully received packets.

![Packet Send](./images/rmc_fig3.png?raw=true)

In addition to the payload the packet header contains the publisher's
network-unique Node ID, a runtime-unique packet ID, and the control
channel IP address and port of the pubhlisher.

A subscriber can check the packet header to determine if the publisher
is currently subscribed to (through an established control channel
connection), or not.

Unsubscribed packets are silently dropped by the subscriber.

Successfully received packets are acknowledged by the subscriber
through an ack message sent over the control channel to the publisher.
The subscriber waits for a period of time to collect as many packets
as possible so that only one ack message needs to be sent for all
packets received. The ack message contains a number of Packet ID
intervals identifying packets that have been received.


## Packet resend

UDP/IP does not guarantee delivery, and published packets are frequently lost
due to network or host issues. Since one or more packets are frequently lost
in the middle of a sequence of packets, the subscriber will end up with holes
in its received packet stream. The mising packets will be omitted in
the Packet ID intervals sent back from the subscriber to the publisher in
an ack message, as shown below.

![Packet Resend](./images/rmc_fig4.png?raw=true)

The publisher will respond to missing packets reported by the
subscriber by resending them over the control channel. This means that
the packet will have guaranteed delivery and does not need additional
resend attempts or acknowledgements.

## Multicast- vs. Control Channel-delivered packets.
The multicast delivery method is used as a performance booster. RMC
can switch to delivering all packets via TCP, albeit at a higher
per-packet cost, in case UDP/IP cannot deliver data.

## Throttling
If a subscriber starts lagging in acknowledging packets to a
subscriber, the publisher can be configure to automatically stop
sending traffic until the backlog has cleared.

If throttling is not enabled, packets will eventually be dropped and
RMC will revert to delivering payloads via the Control Channel, which
is automatically throttled by TCP.

# DETAILED USE CASES

## Announce - Connect

![PlantUML](http://www.plantuml.com/plantuml/png/5Oqn3i8m34LtJW4NY7Uc3Xo0aQro7Oj6Sfme-HRNfvdUzDxR9dWWgjqUnSKYQmoxdq2VJwB1l_GjEEE8gKEQGnr9MgNtwzCcX8PQuSDqhs4emXCKFJDqpqse6_kAqwMw2b9VfqqzB_u1)




# XXXXXXXXXXXXXXXXXXXXX
# TCP Protocol

The TCP connection is initiated from the subscriber to connect to a well-known
IP:port listened to by the publisher.

The following commands are available

|Sender|Receiver|Command   |Description
|------|--------|----------|-----------
|Sub   | Pub    | INIT     | Provisions the newly setup TCP connection
|Pub   | Sub    | PACKET   | A data packet with identical payload to that of a multicast packet
|Sub   | Pub    | ACK      | Acknowledge one or more sequences of packages received multicast


All integers are network ordered.

## INITIATE
When a subscriber sets up a connection it starts off with an ```INIT```
command to register itself and retrieve information about the publisher.

The command has the following layout

### Request [Sub -> Pub]
|Start|Stop|Len | Type  | Name |  Value | Description
|-----|----|----|------ | -----|-------| --------
| 0   | 0  | 1  | uint8 | CMD  |  0     | INIT_REQUEST command
| 1   | 1  | 1  | uint8 | VER  | Protocol version supported

### Reply [Pub -> Sub]
|Start|Stop|Len | Type   | Name     | Value | Description
|-----|----|----|--------| -------- |-------| --------
| 0   | 0  | 1  | uint8  | CMD      | 1     | INIT_REPLY command
| 1   | 1  | 1  | uint8  | VER      | 1     | Protocol version supported
| 2   | 9  | 8  | uint64 | LAST_PID | PID   | Packet ID of last sent packet


## PACKET
A packet is transmitted via the TCP protocol when the publisher detects holes
in the packet sequences ACKed by the subscriber.


### Request [Pub -> Sub]
|Start |Stop|Len | Type  | Name | Value | Description
|-----|----|----|------- | -----| -------| --------
| 0   | 0  | 1  | uint8  | CMD  | 2     | PACKET command
| 1   | 8  | 8  | uint64 | PID  | PID   |Packet ID transmitted
| 9   | 10 | 2  | uint16 | LEN  | Len   | Length of payload
| 11  | 11+Len-1 | Len  | data | DATA | data  | Payload

### Reply [Pub -> Sub]
There is no reply. The packet is acked through an ACK command.

## ACK
A packet is transmitted via the TCP protocol when the publisher detects holes
in the packet sequences ACKed by the subscriber.


### Request [Sub -> Pub]
|Start |Stop|Len | Type  | Name  | Value | Description
|-----|----|----|------- |-------| ------| --------
| 0   | 0  | 1  | uint8  | CMD   | 3     | ACK command
| 1   | 2  | 2  | uint16 | LEN   | Len   | Number of bytes in ack block payload
| 3  | 3+Len-1 | Len | Block payload | BLOCKS  | Block data |Sequence of ack blocks as listed below

The ack block payload is a sequence of acknowledge blocks, where each block
has one of the following formats:

**BLOCK_SINGLE**<br>
Acknowledges a single packet

|Start|Stop|Len | Type    | Name     | Value  | Description
|-----|----|----|-------  | ------   | -------| --------
| 0   | 0  | 1  | uint8   | BLK_TYPE | 0      | BLOCK_SINGLE
| 1   | 8  | 8  | uint64  | PID      | P_ID   | Packed ID of the acknowledged block

**BLOCK_MULTI**<br>
Acknowledges a sequence of packets with consecutive packet ids.

|Start |Stop|Len | Type   | Value | Description
|----- |----|----|-------  |-------| --------
| 0    | 0  | 1  | uint8   | 1     | BLOCK_MULTI
| 1    | 8  | 8  | uint64  | P_ID  | ID of first packet in sequence
| 9    | 17 | 8  | uint64  | P_ID  | ID of last packet in sequence

**BLOCK_MULTI_BITMAP**<br>

Acknowledges a sequence of blocks through a starting packet and a bitmap of
the received and missing packets. The first bit of the bitmap represents the
ack (1) or absense (0) of the packet identified by the start packet id. The ID
of the last packet is the start packet id + the number of bits in the bitmap.

|Start |Stop|Len | Type   | Value | Description
|----- |----|----|-------  |-------| --------
| 0    | 0  | 1  | uint8   | 2     | BLOCK_MULTI_BITMAP
| 1    | 8  | 8  | uint64  | P_ID  | Packet ID of the first bit in the map
| 9    | 10 | 2  | uint16  | Len   | Number of bits in the bitmap
| 11   | 11+(Len/8)-1 | (Len/8) | Bitmap | Block Bitmap |Bitmap of packets successfully received. Last byte is padded with 0


### Reply [Pub -> Sub]
There is no reply.
