# RELIABLE MULTICAST
Reliable UDP Multicast using a separate TCP ack channel per subscriber.

# TESTING

## Test program usage
./rmc_test -?

## Send single signal between publisher and subscriber
Start a publisher that:

1. Emit periodic announce packets to potential subscribrers
2. Waits for one subscriber to connect
3. Sends a single packet (in a single multicast packet)
4. Exits

Window 1:

    ./rmc_test -c 1


Start subscriber that:

1. Waits for an announce packet from a publisher
2. Connects to publisher and sets up subscribtion
3. Reveives however many packets that the publisher has to send
4. Validates all packets
5. Extits

Window 2:

    ./rmc_test -S


## Send a million signals between one publisher and one subscriber

Bandwidth will be dependent on the interface that the multicast is bound to. WiFi is slower than gbit Ethernet.

    ./rmc_test -c 1000000
    ./rmc_test -S

## Send a million signals from two publishers to a single subscriber.

The ```-i``` argument sets up node id to distinguish betwen two publishers.<br>
The ```-e``` argument lists all publishers that the subscriber is to expect announce packets from.<br>

    ./rmc_test -S -e1 -e2
    ./rmc_test -c 1000000 -i1 
    ./rmc_test -c 1000000 -i2
    
## Send a million signals from one publishers to two subscribers

    ./rmc_test -S 
    ./rmc_test -S 
    ./rmc_test -c 1000000 


