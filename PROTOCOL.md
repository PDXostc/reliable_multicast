# RELIABLE UDP MULTICAST PACKETS

Use a reliable TCP backchannel from subscribers to a published to
request resends.

The UDP multicast group is purely a performance booster; all traffic
can be regressed to TCP as UDP losses increase.

# TCP Protocol

The TCP connection is initiated from the subscriber to connect to a well-known IP:port listened to by the publisher.

The following commands are available

|Sender|Receiver|Command   |Description
|------|--------|----------|-----------
|Sub   | Pub    | INIT     | Provisions the newly setup TCP connection 
|Pub   | Sub    | PACKET   | A data packet with identical payload to that of a multicast packet
|Sub   | Pub    | ACK      | Acknowledge one or more sequences of packages received multicast.


All integers are network ordered.

## INITIATE
When a subscriber sets up a connection it starts off with an ```INIT```
command to register itself and retrieve information about the publisher.

The command has the following layout

### Request [Sub -> Pub]
|Start|Stop|Len | Type  | Name |  Value | Description
|-----|----|----|------ | -----|-------| --------
| 0   | 1  | 1  | uint8 | CMD  |  0     | INIT_REQUEST command 
| 1   | 2  | 1  | uint8 | VER  | Protocol version supported. 

### Reply [Pub -> Sub]
|Start|Stop|Len | Type   | Name     | Value | Description
|-----|----|----|--------| -------- |-------| --------
| 0   | 1  | 1  | uint8  | CMD      | 1     | INIT_REPLY command 
| 1   | 2  | 1  | uint8  | VER      | 1     | Protocol version supported.
| 1   | 8  | 8  | uint64 | LAST_PID | PID   | Packet ID of last sent packet


## PACKET
A packet is transmitted via the TCP protocol when the publisher
detects holes in the packet sequences ACKed by the subscriber.


### Request [Pub -> Sub]
|Start |Stop|Len | Type  | Name | Value | Description
|-----|----|----|------- | -----| -------| --------
| 0   | 1  | 1  | uint8  | CMD  | 2     | PACKET command 
| 1   | 8  | 8  | uint64 | PID  | PID   |Packet ID transmitted.
| 9   | 10 | 2  | uint16 | LEN  | Len   | Length of payload
| 11  | 11+Len | Len  | data | DATA | data  | Payload

### Reply [Pub -> Sub]
There is no reply. The packet is acked through an ACK command.

## ACK
A packet is transmitted via the TCP protocol when the publisher
detects holes in the packet sequences ACKed by the subscriber.


### Request [Sub -> Pub]
|Start |Stop|Len | Type  | Name  | Value | Description
|-----|----|----|------- |-------| ------| --------
| 0   | 1  | 1  | uint8  | CMD   | 3     | ACK command 
| 2   | 3  | 2  | uint16 | LEN   | Len   | Number of bytes in ack block payload
| 11  | 11+Len | Len | Block payload | BLOCKS  | Block data |Sequence of ack blocks as listed below

The ack block payload is a sequence of acknowledge blocks, where each block has
one of the following format:

**BLOCK_SINGLE**<br>
Acknowledges a single packet

|Start|Stop|Len | Type    | Name     | Value  | Description
|-----|----|----|-------  | ------   | -------| --------
| 0   | 1  | 1  | uint8   | BLK_TYPE | 0      | BLOCK_SINGLE
| 1   | 8  | 8  | uint64  | PID      | P_ID   | Packed ID of the acknowledged block

**BLOCK_MULTI**<br>
Acknowledges a sequence of packets with consecutive packet ids.

|Start |Stop|Len | Type   | Value | Description
|----- |----|----|-------  |-------| --------
| 0    | 1  | 1  | uint8   | 1     | BLOCK_MULTI
| 1    | 8  | 8  | uint64  | P_ID  | ID of first packet in sequence.
| 9    | 17 | 8  | uint64  | P_ID  | ID of last packet in sequence

**BLOCK_MULTI_BITMAP**<br>

Acknowledges a sequence of blocks through a starting packet and a
bitmap of with received and pissing packets. The first bit of the
bitmap represents the ack (1) or absense (0) of the packet identified
by the start packet id. The ID of the last packet is the start packet
id + the number of bits in the bitmap.

|Start |Stop|Len | Type   | Value | Description
|----- |----|----|-------  |-------| --------
| 0    | 1  | 1  | uint8   | 2     | BLOCK_MULTI_BITMAP
| 1    | 8  | 8  | uint64  | P_ID  | Packet ID of the first bit in the map
| 9    | 10 | 2  | uint16  | Len   | Number of bits in the bitmap
| 11   | 11 + (Len / 8) | (Len / 8) | Bitmap | Block Bitmap |Bitmap of packets successfully received. Last byte is padded with 0.


### Reply [Pub -> Sub]
There is no reply. 
