// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

#include "rmc_proto_test_common.h"
#include "rmc_log.h"



void _test(char* fmt_string, int major, int minor, int error)
{
    if (!error)
        return;

    printf(fmt_string, major, minor, strerror(error));
    exit(255);
}


void poll_add(user_data_t user_data,
              int descriptor,
              rmc_index_t index,
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

    RMC_LOG_INDEX_COMMENT(index,
                          "poll_add(%d)%s%s%s",
                          descriptor,
                          ((action & RMC_POLLREAD)?" read":""),
                          ((action & RMC_POLLWRITE)?" write":""),
                          (!(action & (RMC_POLLREAD | RMC_POLLWRITE)))?" [none]":"");

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, descriptor, &ev) == -1) {
        RMC_LOG_INDEX_FATAL(index, "epoll_ctl(add)");
        exit(255);
    }
}



void poll_modify(user_data_t user_data,
                 int descriptor,
                 rmc_index_t index,
                 rmc_poll_action_t old_action,
                 rmc_poll_action_t new_action)
{
    int epollfd = user_data.i32;
    struct epoll_event ev = {
        .data.u32 = index,
        .events = EPOLLONESHOT
    };

    if (new_action & RMC_POLLREAD)
        ev.events |= EPOLLIN;

    if (new_action & RMC_POLLWRITE)
        ev.events |= EPOLLOUT;

    RMC_LOG_INDEX_DEBUG(index, "poll_modify(%d)%s%s%s",
                        descriptor,
                        ((new_action & RMC_POLLREAD)?" read":""),
                        ((new_action & RMC_POLLWRITE)?" write":""),
                        (!(new_action & (RMC_POLLREAD | RMC_POLLWRITE)))?" [none]":"");

    if (epoll_ctl(epollfd, EPOLL_CTL_MOD, descriptor, &ev) == -1) {
        RMC_LOG_INDEX_FATAL(index, "epoll_ctl(modify): %s", strerror(errno));
        exit(255);
    }
}


void poll_remove(user_data_t user_data,
                 int descriptor,
                 rmc_index_t index)
{
    char buf[16];
    int epollfd = user_data.i32;

    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, descriptor, 0) == -1) {
        RMC_LOG_INDEX_WARNING(index, "epoll_ctl(delete): %s", strerror(errno));
        return;
    }
    RMC_LOG_INDEX_COMMENT(index, "poll_remove()");
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

