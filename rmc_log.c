// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)

// Simple logging


#include "rmc_internal.h"
#include "rmc_log.h"
#include "string.h"
#include <unistd.h>
#include <stdlib.h>

static usec_timestamp_t start_time = 0;

int _rmc_log_level = RMC_LOG_LEVEL_NONE;
int _rmc_log_use_color = -1;
int _rmc_log_use_color_calculated = 0;
FILE *_rmc_log_file = 0;


// Run when the library is loaded
static void __attribute__((constructor)) set_log_level_on_env(void)
{
    char* log_level = getenv("RMC_LOG_LEVEL");

    if (!log_level)
        return;

    rmc_set_log_level(atoi(log_level));
}

void rmc_log_set_start_time(void)
{
    start_time = rmc_usec_monotonic_timestamp();
}

usec_timestamp_t rmc_log_get_start_time(void)
{
    return start_time;
}

void rmc_log_use_color(int use_color)
{
    _rmc_log_use_color = use_color;
    _rmc_log_use_color_calculated = 0;
}

int rmc_set_log_level(int log_level)
{
    if (log_level < RMC_LOG_LEVEL_NONE || log_level > RMC_LOG_LEVEL_DEBUG) {

        rmc_log(RMC_LOG_LEVEL_WARNING, __FUNCTION__, __FILE__, __LINE__, -1,
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

const char* rmc_log_color_light_red()
{
    return _rmc_log_use_color?"\033[38;2;255;204;204m":"";
}

const char* rmc_log_color_red()
{
    return _rmc_log_use_color?"\033[38;2;192;0;0m":"";
}

const char* rmc_log_color_dark_red()
{
    return _rmc_log_use_color?"\033[38;2;255;0;0m":"";
}

const char* rmc_log_color_orange()
{
    return _rmc_log_use_color?"\033[38;2;255;128;0m":"";
}

const char* rmc_log_color_yellow()
{
    return _rmc_log_use_color?"\033[38;2;255;255;0m":"";
}

const char* rmc_log_color_light_blue()
{
    return _rmc_log_use_color?"\033[38;2;0;255;255m":"";
}

const char* rmc_log_color_blue()
{
    return _rmc_log_use_color?"\033[38;2;0;128;255m":"";
}

const char* rmc_log_color_dark_blue()
{
    return _rmc_log_use_color?"\033[38;2;0;0;255m":"";
}

const char* rmc_log_color_light_green()
{
    return _rmc_log_use_color?"\033[38;2;153;255;153m":"";
}


const char* rmc_log_color_green()
{
    return _rmc_log_use_color?"\033[38;2;0;255;0m":"";
}


const char* rmc_log_color_dark_green()
{
    return _rmc_log_use_color?"\033[38;2;0;204;0m":"";
}

const char* rmc_log_color_faint()
{
    return _rmc_log_use_color?"\033[2m":"";
}

const char* rmc_log_color_none()
{
    return _rmc_log_use_color?"\033[0m":"";
}


const char* rmc_index_color(int index)
{
    switch(index) {
    case -1:
        return rmc_log_color_faint();

    case 0:
        return rmc_log_color_dark_blue();

    case 1:
        return rmc_log_color_dark_green();

    case 2:
        return rmc_log_color_light_blue();

    case 3:
        return rmc_log_color_light_green();

    case 4:
        return rmc_log_color_light_red();

    case 5:
        return rmc_log_color_green();

    case 6:
        return rmc_log_color_blue();

    case 7:
        return rmc_log_color_dark_red();

    case 8:
        return rmc_log_color_red();

    default:
        return rmc_log_color_none();
    }
}

void rmc_log(int log_level, const char* func, const char* file, int line, uint16_t index, const char* fmt, ...)
{
    const char* color = 0;
    const char* tag = 0;
    char index_str[32];
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

    switch(index) {
    case RMC_NIL_INDEX:
        strcpy(index_str, "     ");
        break;

    case RMC_MULTICAST_INDEX:
        sprintf(index_str, "%s[UDP]%s", rmc_log_color_orange(), rmc_log_color_none());
        break;

    case RMC_LISTEN_INDEX:
        sprintf(index_str, "%s[CTL]%s", rmc_log_color_yellow(), rmc_log_color_none());
        break;

    default:
        sprintf(index_str, "%s[%.3d]%s", rmc_index_color(index), index, rmc_log_color_none());
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


    fprintf(_rmc_log_file, "%s%s%s %lld %s %s%s:%d%s ",
            color,
            tag,
            rmc_log_color_none(),
            (long long int) (start_time?((rmc_usec_monotonic_timestamp() - start_time)/1000):0) ,
            index_str,
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
