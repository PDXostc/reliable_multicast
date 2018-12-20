// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

// Simple logging


#include "rmc_common.h"
#include "rmc_log.h"
#include "string.h"

static usec_timestamp_t start_time = 0;

int _rmc_log_level = RMC_LOG_LEVEL_NONE;
int _rmc_log_use_color = 1;
FILE *_rmc_log_file = 0;



void rmc_log_set_start_time(void)
{
    start_time = rmc_usec_monotonic_timestamp();
}

void rmc_log_use_color(int use_color)
{
    int _rmc_log_use_color = use_color;
}

void rmc_set_log_level(int log_level)
{
    if (log_level < RMC_LOG_LEVEL_DEBUG || log_level > RMC_LOG_LEVEL_NONE) {
        printf("Illegal log level: %d\n", log_level);
        return;
    }

    _rmc_log_level = log_level;
}

void rmc_log_set_file(FILE* file)
{
    _rmc_log_file = file;
}

const char* rmc_log_color_flashing_red() 
{
    return _rmc_log_use_color?"\033[5;38;2;192;0;0m":"";
}

// Red
const char* rmc_log_color_red() 
{
    return _rmc_log_use_color?"\033[38;2;192;0;0m":"";
}

// Orange
const char* rmc_log_color_orange() 
{
    return _rmc_log_use_color?"\033[38;2;255;128;0m":"";
}

// Blue
const char* rmc_log_color_blue()
{
    return _rmc_log_use_color?"\033[38;2;0;128;255m":"";
}

// Green
const char* rmc_log_color_green()
{
    return _rmc_log_use_color?"\033[38;2;0;204;0m":"";
}

// None
const char* rmc_log_color_none()
{
    return _rmc_log_use_color?"\033[0m":"";
}



void rmc_log(int log_level, const char* func, const char* file, int line, const char* fmt, ...)
{
    const char* color = 0;
    const char* tag = 0;
    char identifier[256];
    va_list ap;
    
    switch(log_level) {
    case RMC_LOG_LEVEL_DEBUG:
        color = rmc_log_color_none();
        tag = "[D]";
        break;

    case RMC_LOG_LEVEL_COMMENT:
        color = rmc_log_color_green();
        tag = "[C]";
        break;

    case RMC_LOG_LEVEL_INFO:
        color = rmc_log_color_blue();
        tag = "[I]";
        break;

    case RMC_LOG_LEVEL_WARNING:
        color = rmc_log_color_orange();
        tag = "[W]";
        break;

    case RMC_LOG_LEVEL_ERROR:
        color = rmc_log_color_red();
        tag = "[E]";
        break;

    case RMC_LOG_LEVEL_FATAL:
        color = rmc_log_color_flashing_red();
        tag = "[F]";
        break;

    default:
        color = rmc_log_color_none();
        tag = "[?]";
        break;
    }

    if (!_rmc_log_file)
        _rmc_log_file = stdout;
    
    // If this is a lambda function, substitute function name with file name
    if (!strcmp(func, "__fn__"))
        sprintf(identifier, "(lambda):%s", file);
    else
        sprintf(identifier, "%s()", func);

    fprintf(_rmc_log_file, "%s%s %ld%s \033[2m%s:%d\033[0m ",
            color,
            tag,
            start_time?((rmc_usec_monotonic_timestamp() - start_time)/1000):0 ,
            rmc_log_color_none(),
            identifier,
            line);
    va_start(ap, fmt);
    vfprintf(_rmc_log_file, fmt, ap);
    va_end(ap);
    fputc('\n', _rmc_log_file);
}
// 8592



