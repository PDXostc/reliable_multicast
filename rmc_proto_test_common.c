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

int _descriptor(rmc_context_t* ctx,
                       rmc_connection_index_t index)
{
    switch(index) {
    case RMC_MULTICAST_RECV_INDEX:
        return ctx->mcast_recv_descriptor;

    case RMC_MULTICAST_SEND_INDEX:
        return ctx->mcast_send_descriptor;

    case RMC_LISTEN_INDEX:
        return ctx->listen_descriptor;

    default:
        return ctx->connections[index].descriptor;

    }
}

void _test(char* fmt_string, int major, int minor, int error)
{
    if (!error)
        return;

    printf(fmt_string, major, minor, strerror(error));
    exit(255);
}


void poll_add(rmc_context_t* ctx,
              int descriptor,
              rmc_connection_index_t index,
              rmc_poll_action_t action)
{
    char buf[16];
    int epollfd = rmc_user_data(ctx).i32;
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



void poll_modify(rmc_context_t* ctx,
                 int descriptor,
                 rmc_connection_index_t index,
                 rmc_poll_action_t old_action,
                 rmc_poll_action_t new_action)
{
    char buf[16];
    int epollfd = rmc_user_data(ctx).i32;
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


void poll_remove(rmc_context_t* ctx,
                 int descriptor,
                 rmc_connection_index_t index)
{
    char buf[16];
    int epollfd = rmc_user_data(ctx).i32;

    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, descriptor, 0) == -1) {
        perror("epoll_ctl(delete)");
        exit(255);
    }
    printf("poll_remove(%s)\n", _index(index, buf));
}



#define RMC_MIN(x,y) ((x)<(y)?(x):(y))

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


int process_events(rmc_context_t* ctx, int epollfd, usec_timestamp_t timeout, int major, int* tick_ind)
{
    struct epoll_event events[RMC_MAX_CONNECTIONS];
    char buf[16];
    int nfds = 0;

    *tick_ind = 0;

    nfds = epoll_wait(epollfd, events, RMC_MAX_CONNECTIONS, (timeout == -1)?-1:(timeout / 1000));
    if (nfds == -1) {
        perror("epoll_wait");
        exit(255);
    }

    // Timeout
    if (nfds == 0) 
        return ETIME;


    // printf("poll_wait(): %d results\n", nfds);

    while(nfds--) {
        int res = 0;
        uint8_t op_res = 0;
        rmc_connection_index_t c_ind = events[nfds].data.u32;

//        printf("poll_wait(%s:%d)%s%s%s\n",
//               _index(c_ind, buf), _descriptor(ctx, c_ind),
//               ((events[nfds].events & EPOLLIN)?" read":""),
//
//               ((events[nfds].events & EPOLLOUT)?" write":""),
//               ((events[nfds].events & EPOLLHUP)?" disconnect":""));

        // Figure out what to do.
        if (events[nfds].events & EPOLLHUP) {
            _test("rmc_proto_test[%d.%d] process_events():rmc_close_tcp(): %s\n",
                  major, 11, rmc_close_connection(ctx, c_ind));
            continue;
        }

        if (events[nfds].events & EPOLLIN) {
            errno = 0;
            res = rmc_read(ctx, c_ind, &op_res);
            // Did we read a loopback message we sent ourselves?
            printf("process_events(%s):%s\n", _op_res_string(op_res), strerror(res));
            if (res == ELOOP)
                continue;       

            _test("rmc_proto_test[%d.%d] process_events():rmc_read(): %s\n", major, 1, res);
                
            // If this was a connection call processed, we can continue.
            if (op_res == RMC_READ_ACCEPT)
                continue;

            if (op_res == RMC_READ_MULTICAST)
                *tick_ind = 1;
        }

        if (events[nfds].events & EPOLLOUT) {
            _test("rmc_proto_test[%d.%d] process_events():rmc_write(): %s\n",
                  major, 10,
                  rmc_write(ctx, c_ind, &op_res));

            printf("op_res: %s\n", _op_res_string(op_res));

            if (op_res == RMC_WRITE_MULTICAST)
                *tick_ind = 1;
        }
    }

    return 0;
}

