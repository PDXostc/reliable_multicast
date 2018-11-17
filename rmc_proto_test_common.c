// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "rmc_proto_test_common.h"


// We need user data that points out both
// the pollset file descriptor and the context associated.

char* _index(rmc_connection_index_t index, char* res)
{
    switch(index) {
    case RMC_MULTICAST_SEND_INDEX:
        return strcpy(res, "mcast_send");

    case RMC_MULTICAST_RECV_INDEX:
        return strcpy(res, "mcast_recv");


    case RMC_LISTEN_INDEX:
        return strcpy(res, "listen");

    default:
        sprintf(res, "%.3d", index);
        return res;
    }
    return 0;
}


void _test(char* fmt_string, int major, int minor, int error)
{
    if (!error)
        return;

    printf(fmt_string, major, minor, strerror(error));
    exit(255);
}


void poll_add(user_data_t user_data,
              int descriptor,
              rmc_connection_index_t index,
              rmc_poll_action_t action)
{
    char buf[16];
    int epollfd = user_data.i32;
    struct epoll_event ev = {
        .data.u32 = index,
        .events = EPOLLONESHOT
    };

    if (action & RMC_POLLREAD)
        ev.events |= EPOLLIN;

    if (action & RMC_POLLWRITE)
        ev.events |= EPOLLOUT;

    printf("poll_add(%s:%d)%s%s%s\n",
           _index(index, buf),
           descriptor,
           ((action & RMC_POLLREAD)?" read":""),
           ((action & RMC_POLLWRITE)?" write":""),
           (!(action & (RMC_POLLREAD | RMC_POLLWRITE)))?" [none]":"");

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, descriptor, &ev) == -1) {
        perror("epoll_ctl(add)");
        exit(255);
    }
}



void poll_modify(user_data_t user_data,
                 int descriptor,
                 rmc_connection_index_t index,
                 rmc_poll_action_t old_action,
                 rmc_poll_action_t new_action)
{
    char buf[16];
    int epollfd = user_data.i32;
    struct epoll_event ev = {
        .data.u32 = index,
        .events = EPOLLONESHOT
    };

    if (new_action & RMC_POLLREAD)
        ev.events |= EPOLLIN;

    if (new_action & RMC_POLLWRITE)
        ev.events |= EPOLLOUT;

//    printf("poll_modify(%s:%d)%s%s%s\n",
//           _index(index, buf),
//           descriptor,
//           ((new_action & RMC_POLLREAD)?" read":""),
//           ((new_action & RMC_POLLWRITE)?" write":""),
//           (!(new_action & (RMC_POLLREAD | RMC_POLLWRITE)))?" [none]":"");

    if (epoll_ctl(epollfd, EPOLL_CTL_MOD, descriptor, &ev) == -1) {
        perror("epoll_ctl(modify)");
        exit(255);
    }
}


void poll_remove(user_data_t user_data,
                 int descriptor,
                 rmc_connection_index_t index)
{
    char buf[16];
    int epollfd = user_data.i32;

    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, descriptor, 0) == -1) {
        perror("epoll_ctl(delete)");
        exit(255);
    }
    printf("poll_remove(%s)\n", _index(index, buf));
}




char* _op_res_string(uint8_t res)
{
    switch(res) {
    case RMC_ERROR:
        return "error";
        
    case RMC_READ_MULTICAST:
        return "read multicast";
 
    case RMC_READ_MULTICAST_LOOPBACK:
        return "multicast loopback";
 
    case RMC_READ_MULTICAST_NEW:
        return "new multicast";

     case RMC_READ_MULTICAST_NOT_READY:
        return "multicast not ready";
        
    case RMC_READ_TCP:
        return "read tcp";
        
    case RMC_READ_ACCEPT:
        return "accept";
        
    case RMC_READ_DISCONNECT:
        return "disconnect";

    case RMC_WRITE_MULTICAST:
        return "write multicast";

    case RMC_COMPLETE_CONNECTION:
        return "complete connection";

    case RMC_WRITE_TCP:
        return "tcp write";

    default:
        return "[unknown]";
        
    }
}

