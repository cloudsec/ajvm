/*
 * Copyright (C) 2012, 2013 wzt         http://www.cloud-sec.org
 *
 * jvm.c
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

#include "jvm.h"
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
	fprintf(stdout, "-s [class_name]\t\tDisplay class file info.\n");
	fprintf(stdout, "-d [class_name]\t\tDisassember class file.\n");
	fprintf(stdout, "-v\t\t\tShow jvm version.\n");
}

int jvm_arg_init(void)
{
	jvm_arg = (JVM_ARG *)malloc(sizeof(JVM_ARG));
	if (!jvm_arg) {
		__error("malloc failed.");
		return -1;
	}
	memset(jvm_arg, '\0', sizeof(JVM_ARG));

	strcpy(jvm_arg->class_path, ".");
	
	return 0;
}

void print_jvm_arg(void)
{
	printf("class path: %s\n", jvm_arg->class_path);
}

int show_jvm_class(JVM_ARG *arg)
{
        if (log_init() == -1)
                return -1;

        if (calltrace_init() == -1)
                return -1;

        INIT_LIST_HEAD(&jvm_class_list_head);
        init_class_parse();

        if (!jvm_parse_class_file(arg->class_path, arg->class_path)) {
		calltrace_exit();
                return -1;
	}

	return 0;
}

int disass_jvm_class(JVM_ARG *arg)
{
        struct list_head *s, *q;
	CLASS *r;

	arg->print_class = 0;
	if (show_jvm_class(arg) == -1)
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
        if (log_init() == -1)
                return -1;

	if (calltrace_init() == -1)
		return -1;

	INIT_LIST_HEAD(&jvm_class_list_head);
        init_class_parse();

	if (jvm_stack_init() == -1)
		return -1;

	if (jvm_interp_env_init() == -1)
		return -1;

        if (!jvm_load_class(arg->class_path, class_name))
		return -1;

	return 0;
}

int jvm_run(char *class_name)
{
	CLASS_METHOD *method;

	method = lookup_class_method(&jvm_class_list_head, class_name, "main");
	if (!method) {
		printf("jvm not found method main().\n");
		return -1;
	}
	printf("jvm found method: main()\n");

	jvm_pc_init(method);
	if (interp_bytecode(method) == -1) {
		printf("interp bytecode failed.\n");
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

	if (jvm_arg_init() == -1)
		return -1;

	while ((c = getopt(argc, argv, "c:s:d:v")) != -1) {
		switch (c) {
		case 'c':
			memset(jvm_arg->class_path, '\0', 1024);
			strcpy(jvm_arg->class_path, optarg);
			break;
		case 's':
			jvm_arg->print_class = 1;
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
			printf("Bad option.\n");
			jvm_usage(argv[0]);
			return -1;
		}
	}

	if (jvm_arg->print_class) {
		show_jvm_class(jvm_arg);
		return 0;
	}
	
	if (jvm_arg->disass_class) {
		disass_jvm_class(jvm_arg);
		return 0;
	}

	GET_BP(top_rbp);
	if (jvm_init(jvm_arg, argv[argc - 1]) == -1)
		return 0;

	if (jvm_run(argv[argc - 1]) == -1)
		return -1;

	jvm_exit();

        return 0;
}
