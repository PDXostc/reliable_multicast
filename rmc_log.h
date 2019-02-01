// Copyright (C) 2018, Jaguar Land Rover
// This program is licensed under the terms and conditions of the
// Mozilla Public License, version 2.0.  The full text of the 
// Mozilla Public License is at https://www.mozilla.org/MPL/2.0/
//
// Author: Magnus Feuer (mfeuer1@jaguarlandrover.com)


#ifndef __RMC_LOG_H__
#define __RMC_LOG_H__
#include <stdio.h>
#include <stdarg.h>

#define RMC_LOG_LEVEL_NONE 0
#define RMC_LOG_LEVEL_FATAL 1
#define RMC_LOG_LEVEL_ERROR 2
#define RMC_LOG_LEVEL_WARNING 3
#define RMC_LOG_LEVEL_INFO 4
#define RMC_LOG_LEVEL_COMMENT 5
#define RMC_LOG_LEVEL_DEBUG 6

extern char* rmc_log_timestamp(char* target);
extern void rmc_log_set_start_time(void);
extern usec_timestamp_t rmc_log_get_start_time(void);
extern void rmc_log_use_color(int use_color);
extern int rmc_set_log_level(int log_level);
extern void rmc_log(int log_level, const char* func, const char* file, int line, uint16_t index, const char* fmt, ...);
extern const char* rmc_log_color_none();
extern const char* rmc_log_color_faint();
extern const char* rmc_log_color_green();
extern const char* rmc_log_color_blue();
extern const char* rmc_log_color_orange();
extern const char* rmc_log_color_red();
extern const char* rmc_log_color_flashing_red();
extern const char* rmc_index_color(int index);

extern int _rmc_log_level;

#ifndef RMC_NIL_INDEX
#define RMC_NIL_INDEX 0x7FFF
#endif

#define RMC_LOG_DEBUG(fmt, ...) { if (_rmc_log_level >= RMC_LOG_LEVEL_DEBUG) rmc_log(RMC_LOG_LEVEL_DEBUG, __FUNCTION__, __FILE__, __LINE__, RMC_NIL_INDEX, fmt, ##__VA_ARGS__ ); }
#define RMC_LOG_COMMENT(fmt, ...) { if (_rmc_log_level >= RMC_LOG_LEVEL_COMMENT) rmc_log(RMC_LOG_LEVEL_COMMENT, __FUNCTION__, __FILE__, __LINE__, RMC_NIL_INDEX, fmt, ##__VA_ARGS__ ); }
#define RMC_LOG_INFO(fmt, ...) { if (_rmc_log_level >= RMC_LOG_LEVEL_INFO) rmc_log(RMC_LOG_LEVEL_INFO, __FUNCTION__, __FILE__, __LINE__, RMC_NIL_INDEX, fmt, ##__VA_ARGS__); }
#define RMC_LOG_WARNING(fmt, ...) { if (_rmc_log_level >= RMC_LOG_LEVEL_WARNING) rmc_log(RMC_LOG_LEVEL_WARNING, __FUNCTION__, __FILE__, __LINE__, RMC_NIL_INDEX, fmt, ##__VA_ARGS__); }
#define RMC_LOG_ERROR(fmt, ...) { if (_rmc_log_level >= RMC_LOG_LEVEL_ERROR) rmc_log(RMC_LOG_LEVEL_ERROR, __FUNCTION__, __FILE__, __LINE__, RMC_NIL_INDEX, fmt, ##__VA_ARGS__); }
#define RMC_LOG_FATAL(fmt, ...) { if (_rmc_log_level >= RMC_LOG_LEVEL_FATAL) rmc_log(RMC_LOG_LEVEL_FATAL, __FUNCTION__, __FILE__, __LINE__, RMC_NIL_INDEX, fmt, ##__VA_ARGS__); }

#define RMC_LOG_INDEX_DEBUG(index, fmt, ...) { if (_rmc_log_level >= RMC_LOG_LEVEL_DEBUG) rmc_log(RMC_LOG_LEVEL_DEBUG, __FUNCTION__, __FILE__, __LINE__, index, fmt, ##__VA_ARGS__ ); }
#define RMC_LOG_INDEX_COMMENT(index, fmt, ...) { if (_rmc_log_level >= RMC_LOG_LEVEL_COMMENT) rmc_log(RMC_LOG_LEVEL_COMMENT, __FUNCTION__, __FILE__, __LINE__, index, fmt, ##__VA_ARGS__ ); }
#define RMC_LOG_INDEX_INFO(index, fmt, ...) { if (_rmc_log_level >= RMC_LOG_LEVEL_INFO) rmc_log(RMC_LOG_LEVEL_INFO, __FUNCTION__, __FILE__, __LINE__, index, fmt, ##__VA_ARGS__); }
#define RMC_LOG_INDEX_WARNING(index, fmt, ...) { if (_rmc_log_level >= RMC_LOG_LEVEL_WARNING) rmc_log(RMC_LOG_LEVEL_WARNING, __FUNCTION__, __FILE__, __LINE__, index, fmt, ##__VA_ARGS__); }
#define RMC_LOG_INDEX_ERROR(index, fmt, ...) { if (_rmc_log_level >= RMC_LOG_LEVEL_ERROR) rmc_log(RMC_LOG_LEVEL_ERROR, __FUNCTION__, __FILE__, __LINE__, index, fmt, ##__VA_ARGS__); }
#define RMC_LOG_INDEX_FATAL(index, fmt, ...) { if (_rmc_log_level >= RMC_LOG_LEVEL_FATAL) rmc_log(RMC_LOG_LEVEL_FATAL, __FUNCTION__, __FILE__, __LINE__, index, fmt, ##__VA_ARGS__); }

#endif // __RMC_LOG_H__
