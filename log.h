/*
 * log.h - Zhitong Wang 2012, 2013   <zhitong.wangzt@aliyun-inc.com>
 */

#ifndef LOG_H
#define LOG_H

#include <stdarg.h>
#include <pthread.h>

#define LOG_NUM                 10
#define LOG_SIZE                (20 * 1024 * 1024)      // 20M

typedef enum {
        LOG_FATAL = 0,
        LOG_ERROR,
        LOG_INFO,
        LOG_DEBUG,
        LOG_DEBUG1,
        LOG_DEBUG2,
        LOG_NOLEVEL
}LOG_LEVEL;

typedef struct log_arg {
        int log_level;
        int log_file_num;
        int log_size;
        int curr_log_num;
        char log_path[1024];
        char curr_log[1024];
        FILE *log_fp;
        pthread_mutex_t log_lock;
}LOG_ARG;

int log_init(char *log_path, int log_level);
int debug_init(int debug_level);
void log_destroy(void);

void log_lock(void);
void log_unlock(void);
#define debug(fmt, ...)         do_log(LOG_DEBUG,  __FILE__,           \
                                        __FUNCTION__, __LINE__,                 \
                                        fmt, ##__VA_ARGS__);

#define __debug(fmt, ...)       do_debug(LOG_DEBUG, __FILE__,         \
                                        __FUNCTION__, __LINE__,                 \
                                        fmt, ##__VA_ARGS__);

#define debug1(fmt, ...)        do_log(LOG_DEBUG1,  __FILE__,          \
                                        __FUNCTION__, __LINE__,                 \
                                        fmt, ##__VA_ARGS__);

#define __debug1(fmt, ...)      do_debug(LOG_DEBUG1,  __FILE__,        \
                                        __FUNCTION__, __LINE__,                 \
                                        fmt, ##__VA_ARGS__);

#define debug2(fmt, ...)        do_log(LOG_DEBUG2, __FILE__,          \
                                        __FUNCTION__, __LINE__,                 \
                                        fmt, ##__VA_ARGS__);

#define __debug2(fmt, ...)      do_debug(LOG_DEBUG2, __FILE__,        \
                                        __FUNCTION__, __LINE__,                 \
                                        fmt, ##__VA_ARGS__);

#define fatal(fmt, ...)         do_log(LOG_FATAL, __FILE__,           \
                                        __FUNCTION__, __LINE__,                 \
                                        fmt, ##__VA_ARGS__);

#define __fatal(fmt, ...)       do_debug(LOG_FATAL, __FILE__,         \
                                        __FUNCTION__, __LINE__,                 \
                                        fmt, ##__VA_ARGS__);

#define error(fmt, ...)         do_log(LOG_ERROR, __FILE__,           \
                                        __FUNCTION__, __LINE__,                 \
                                        fmt, ##__VA_ARGS__);

#define __error(fmt, ...)       do_debug(LOG_ERROR, __FILE__,         \
                                        __FUNCTION__, __LINE__,                 \
                                        fmt, ##__VA_ARGS__);

#define info(fmt, ...)          do_log(LOG_INFO, __FILE__,            \
                                        __FUNCTION__, __LINE__,                 \
                                        fmt, ##__VA_ARGS__);

#define __info(fmt, ...)        do_debug(LOG_INFO, __FILE__,          \
                                        __FUNCTION__, __LINE__,                 \
                                        fmt, ##__VA_ARGS__);

#endif
