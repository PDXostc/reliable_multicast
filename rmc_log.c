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
#include <unistd.h>

static usec_timestamp_t start_time = 0;

int _rmc_log_level = RMC_LOG_LEVEL_NONE;
int _rmc_log_use_color = -1;
int _rmc_log_use_color_calculated = 0;
FILE *_rmc_log_file = 0;



void rmc_log_set_start_time(void)
{
    start_time = rmc_usec_monotonic_timestamp();
}

void rmc_log_use_color(int use_color)
{
    _rmc_log_use_color = use_color;
    _rmc_log_use_color_calculated = 0;
}

int rmc_set_log_level(int log_level)
{
    if (log_level < RMC_LOG_LEVEL_NONE || log_level > RMC_LOG_LEVEL_DEBUG) {

        rmc_log(RMC_LOG_LEVEL_WARNING, __FUNCTION__, __FILE__, __LINE__,
                "Illegal log level: %d. Legal values [%d-%d]", log_level, RMC_LOG_LEVEL_NONE, RMC_LOG_LEVEL_DEBUG);
        return 1;
    }

    _rmc_log_level = log_level;
    return 0;
}

void rmc_log_set_file(FILE* file)
{
    _rmc_log_file = file;

    // If necessary, recalculate if we should use colors or not.

    if (_rmc_log_use_color_calculated) {
        if (isatty(fileno(_rmc_log_file)))
            _rmc_log_use_color = 1;
        else
            _rmc_log_use_color = 0;
    }
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

// Faint
const char* rmc_log_color_faint()
{
    return _rmc_log_use_color?"\033[2m":"";
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
    va_list ap;
    

    // Default rmc_log_file, if not set.
    if (!_rmc_log_file)
        _rmc_log_file = stdout;

    // If use color is -1, then check if we are on a tty or not
    if (_rmc_log_use_color == -1) {
        _rmc_log_use_color_calculated = 1;

        if (isatty(fileno(_rmc_log_file)))
            _rmc_log_use_color = 1;
        else
            _rmc_log_use_color = 0;
    }

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



    fprintf(_rmc_log_file, "%s%s %ld%s %s%s:%d%s ",
            color,
            tag,
            start_time?((rmc_usec_monotonic_timestamp() - start_time)/1000):0 ,
            rmc_log_color_none(),
            rmc_log_color_faint(),
            file,
            line,
            rmc_log_color_none());
    va_start(ap, fmt);
    vfprintf(_rmc_log_file, fmt, ap);
    va_end(ap);
    fputc('\n', _rmc_log_file);
}
// 8592



