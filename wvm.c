/*
 * Copyright (C) 2012, 2013, 2014 wzt         http://www.cloud-sec.org
 *
 * wvm.c
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <assert.h>

#include "wvm.h"
#include "trace.h"
#include "type.h"
#include "list.h"
#include "log.h"

extern int disass_bytecode(struct list_head *list_head);

void jvm_usage(const char *proc)
{
        fprintf(stdout, "usage: %s <option>\n\n", proc);
	fprintf(stdout, "option:\n");
	fprintf(stdout, "-c [class_path]\t\tInterpt java bytecode.\n");
	fprintf(stdout, "-d [class_name]\t\tDisassember class file.\n");
	fprintf(stdout, "-v\t\t\tShow jvm version.\n");
}

void jvm_mem_init(void)
{
	jvm_thread_mem = mem_cache_init(SLAB_SIZE_NUM);
        assert(jvm_thread_mem != NULL);
}

int jvm_arg_init(void)
{
	jvm_arg = (JVM_ARG *)calloc(1, sizeof(JVM_ARG));
	if (!jvm_arg) {
		printf("malloc failed.");
		return -1;
	}

	jvm_arg->log_level = JVM_LOG_LEVEL;
	jvm_arg->log_num = JVM_LOG_NUM;
	jvm_arg->log_size = JVM_LOG_SIZE;

	strcpy(jvm_arg->log_path, JVM_LOG_PATH);
	strcpy(jvm_arg->class_path, ".");
	
	return 0;
}

void jvm_arg_exit(void)
{
	free(jvm_arg);
}

void print_jvm_arg(void)
{
	printf("class path: %s\n", jvm_arg->class_path);
}

int parse_jvm_class(JVM_ARG *arg)
{
        INIT_LIST_HEAD(&jvm_class_list_head);
        init_class_parse();

        if (!jvm_parse_class_file(arg->class_path, arg->class_path)) {
		error("jvm parse class file: %s failed.\n", arg->class_path);
                return -1;
	}
	debug2("jvm parse class file: %s ok.\n", arg->class_path);

	return 0;
}

int disass_jvm_class(JVM_ARG *arg)
{
        struct list_head *s, *q;
	CLASS *r;

	arg->print_class = 0;
	if (parse_jvm_class(arg) == -1)
		return -1;

        list_for_each(q, (&jvm_class_list_head)) {
                r = list_entry(q, CLASS, list);
		if (r) {
			disass_bytecode((&r->method_list_head));
		}
        }

	return 0;
}

int jvm_init(JVM_ARG *arg, const char *class_name)
{
	INIT_LIST_HEAD(&jvm_class_list_head);

        init_class_parse();

	INIT_LIST_HEAD(&jvm_obj_list_head);

	if (jvm_stack_init() == -1)
		return -1;
	debug2("jvm stack init ok.\n");

	if (jvm_interp_env_init() == -1)
		return -1;
	debug2("jvm interp env init ok.\n");

        if (!jvm_load_class(arg->class_path, class_name))
		return -1;

	return 0;
}

int jvm_run(char *class_name)
{
	CLASS_METHOD *method;

	method = lookup_class_method(&jvm_class_list_head, class_name, "main");
	if (!method) {
		error("jvm not found method main().\n");
		return -1;
	}
	debug2("jvm found method: main()\n");

	jvm_pc_init(method);
	if (interp_bytecode(method) == -1) {
		error("interp bytecode failed.\n");
		return -1;
	}

	return 0;
}

void jvm_exit(void)
{
	exit_class_parse();
}

void jvm_banner(void)
{
	fprintf(stdout, "jvm v%2.2f\t%s\n", JVM_VERSION, JVM_BANNER);
}

int main(int argc, char **argv)
{
	char c;

        if (argc == 1) {
                jvm_usage(argv[0]);
                return 0;
        }
	
	GET_BP(top_bp)

	if (jvm_arg_init() == -1)
		return -1;

	while ((c = getopt(argc, argv, "c:s:d:v")) != -1) {
		switch (c) {
		case 'c':
			memset(jvm_arg->class_path, '\0', 1024);
			strcpy(jvm_arg->class_path, optarg);
			break;
		case 'd':
			jvm_arg->disass_class = 1;
			memset(jvm_arg->class_path, '\0', 1024);
			strcpy(jvm_arg->class_path, optarg);
			break;
		case 'v':
			jvm_banner();
			return ;
		default:
			printf("Bad option, see -v for help.\n");
			jvm_usage(argv[0]);
			return -1;
		}
	}

        if (log_init(jvm_arg->log_path, jvm_arg->log_level,
			jvm_arg->log_size, jvm_arg->log_num) == -1)
                return -1;

        if (calltrace_init() == -1) {
		log_destroy();
		return -1;
	}

	jvm_mem_init();

	if (jvm_arg->print_class) {
		parse_jvm_class(jvm_arg);
		jvm_arg_exit();
		calltrace_destroy();
		log_destroy();
		return 0;
	}
	
	if (jvm_arg->disass_class) {
		disass_jvm_class(jvm_arg);
		jvm_arg_exit();
		calltrace_destroy();
		log_destroy();
		return 0;
	}

	if (jvm_init(jvm_arg, argv[argc - 1]) == -1) {
		jvm_arg_exit();
		calltrace_destroy();
		log_destroy();
		return 0;
	}

	if (jvm_run(argv[argc - 1]) == -1) {
		jvm_arg_exit();
		calltrace_destroy();
		log_destroy();
		return -1;
	}

        return 0;
}
