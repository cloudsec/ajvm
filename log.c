/*
 * Copyright (C) 2012, 2013, 2014 zhitong.wangzt@aliyun-inc.com
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <pthread.h>

#include "log.h"

LOG_ARG *log_arg = NULL;

int __get_process_name(char *proc_path, char *proc_name)
{
        FILE *fp;
        char buf[1024], tmp[64];

        fp = fopen(proc_path, "r");
        if (!fp) {
                perror("fopen");
                return -1;
        }
        while (fgets(buf, 1024, fp) != NULL) {
                if (strstr(buf, "Name") != NULL) {
                        sscanf(buf, "%s %s", tmp,  proc_name);
                        fclose(fp);
                        return 0;
                }
        }

        fclose(fp);
        return -1;
}

int get_process_name(char *proc_name)
{
        DIR *dir;
        struct dirent *ptr;
        char tmp[1024];
        pid_t pid;

        if ((dir = opendir("/proc")) == NULL) {
                perror("opendir");
                return -1;
        }

        while ((ptr = readdir(dir)) != NULL) {
                if (!strcmp(ptr->d_name, ".") || !strcmp(ptr->d_name, ".."))
                        continue;

                pid = strtoul(ptr->d_name, '\0', 10);
                if (pid == getpid()) {
                        snprintf(tmp, sizeof(tmp), "/proc/%s/status", ptr->d_name);
                        if (!__get_process_name(tmp, proc_name)) {
                                closedir(dir);
                                return 0;
                        }
                }
        }

        closedir(dir);
        return -1;
}

int log_init(char *log_path, int log_level, int log_size, int log_num)
{
        char buff[1024];
        char proc_name[64];
        char pwd[1024];

	if (log_level > LOG_NOLEVEL ||
		log_size > MAX_LOG_SIZE ||
		log_num > MAX_LOG_NUM) {
		printf("log argument error.\n");
		return -1;
	}

        memset(proc_name, '\0', 64);
        if (get_process_name(proc_name) == -1)
                return -1;

        if (!getcwd(pwd, 1024))
                return -1;

        log_arg = (LOG_ARG *)malloc(sizeof(LOG_ARG));
        if (!log_arg) {
                fprintf(stderr, "Malloc failed.\n");
                return -1;
        }

        log_arg->log_level = log_level;
        log_arg->log_file_num = log_num;
        log_arg->curr_log_num = 0;

        /* the kernel will write data into memory cache first,
         * using fstat to get the file size is not correctly,
         * To solove this case, it can wait the data until kernel
         * write them to the disk from memory cache, but in order to
         * improve the performance, we just raise the log_size:::-).
         */
        log_arg->log_size = log_size * 1024 * 1024;
        snprintf(log_arg->log_path, 1024, "%s/%d", log_path, getpid());
        pthread_mutex_init(&log_arg->log_lock, NULL);

        if (mkdir(log_arg->log_path, 0700) == -1) {
                perror("mkdir");
                free(log_arg);
                return -1;
        }

        snprintf(buff, sizeof(buff), "%s/log.1", log_arg->log_path);
        strcpy(log_arg->curr_log, buff);

        log_lock();
        log_arg->log_fp = fopen(buff, "w+");
        if (!log_arg->log_fp) {
                perror("fopen");
                log_unlock();
                free(log_arg);
                return -1;
        }
        log_unlock();

        return 0;
}

void do_log(LOG_LEVEL log_level, char *file_name, char *function,
                int line, char *fmt, ...)
{
        struct tm *log_now;
        time_t log_t;
        va_list arg;
        char tmp[1024];
        char buf[4096];

        assert(log_arg->log_level != LOG_NOLEVEL);
        if (log_level > log_arg->log_level)
                return ;

        va_start(arg, fmt);
        vsprintf(tmp, fmt, arg);
        va_end(arg);

        time(&log_t);
        log_now = localtime(&log_t);
        snprintf(buf, sizeof(buf),
                "%04d-%02d-%02d %02d:%02d:%02d -- %s:%s(%d): %s",
                log_now->tm_year + 1900, log_now->tm_mon + 1,
                log_now->tm_mday, log_now->tm_hour, log_now->tm_min,
                log_now->tm_sec, file_name, function, line, tmp);

        //sync();
        log_lock();
        if (check_log_size() == -1) {
                log_unlock();
                return ;
        }

	fflush(log_arg->log_fp);
        fprintf(log_arg->log_fp, "%s", buf);
        log_unlock();
}

int debug_init(int debug_level)
{
        log_arg = (LOG_ARG *)malloc(sizeof(LOG_ARG));
        if (!log_arg) {
                fprintf(stderr, "Malloc failed.\n");
                return -1;
        }

        log_arg->log_level = debug_level;
        log_arg->log_file_num = LOG_NUM;
        log_arg->curr_log_num = 0;

        pthread_mutex_init(&log_arg->log_lock, NULL);

        return 0;
}

void do_debug(LOG_LEVEL log_level, char *file_name, char *function,
                int line, char *fmt, ...)
{
        va_list arg;
        char tmp[1024];
        char buf[4096];

        assert(log_arg->log_level != LOG_NOLEVEL);
        if (log_level > log_arg->log_level)
                return ;

        va_start(arg, fmt);
        vsprintf(tmp, fmt, arg);
        va_end(arg);

        snprintf(buf, sizeof(buf), "%s:%s(%d): %s", file_name, function, line, tmp);

        log_lock();
        fprintf(stdout, "%s", buf);
        log_unlock();
}

int extract_log_num(void)
{
        char *s;

        assert(s != NULL);
	s = strchr(log_arg->curr_log, '.');
	if (s)
        	return atoi(s + 1);
	else
		return 0;
}

/* already hold the log_lock. */
int expand_log(void)
{
	struct stat f_stat;
        int log_num;
        char tmp[1024];

	/* close current log file first. */
        fclose(log_arg->log_fp);

        log_num = extract_log_num();
	if (log_num == 0)
		return -1;

	printf("current log num: %d\n", log_num);
        if (log_num == log_arg->log_file_num) {
                snprintf(tmp, sizeof(tmp), "%s/log.%d", log_arg->log_path, 1);
        }
        else {
                snprintf(tmp, sizeof(tmp), "%s/log.%d", log_arg->log_path, 
			log_num + 1);
        }
	printf("new log: %s\n", tmp);

	/* log file already exist. */
	if (stat(tmp, &f_stat) == 0) {
		printf("log already exist.\n");
		if (unlink(tmp) == -1)
			return -1;
		printf("delete log ok.\n");
	}

        memset(log_arg->curr_log, '\0', 1024);
        strcpy(log_arg->curr_log, tmp);
        log_arg->log_fp = fopen(log_arg->curr_log, "w+");
        if (!log_arg->log_fp) {
                return -1;
        }

        return 0;
}

int check_log_size(void)
{
        struct stat f_stat;

        if (stat(log_arg->curr_log, &f_stat) == -1)
                return -1;

        if (f_stat.st_size >= log_arg->log_size) {
                if (expand_log() == -1) {
                        return -1;
                }
        }

        return 0;
}

void log_close(void)
{
        log_lock();
        fclose(log_arg->log_fp);
        log_unlock();
}

void log_destroy(void)
{
        log_close();
        pthread_mutex_destroy(&log_arg->log_lock);
        free(log_arg);
}

void log_lock(void)
{
        pthread_mutex_lock(&log_arg->log_lock);
}

void log_unlock(void)
{
        pthread_mutex_unlock(&log_arg->log_lock);
}
