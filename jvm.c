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

void jvm_usage(const char *proc)
{
        fprintf(stdout, "usage: %s <option>\n\n", proc);
	fprintf(stdout, "option:\n");
	fprintf(stdout, "-p [class_path]\t\tInterpt java bytecode.\n");
	fprintf(stdout, "-s [class_name]\t\tDisplay class file info.\n");
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

int jvm_init(JVM_ARG *arg, const char *class_name)
{
        if (log_init() == -1)
                return -1;

	if (calltrace_init() == -1)
		return -1;

	INIT_LIST_HEAD(&jvm_class_list_head);
        init_class_parse();

        if (!jvm_load_class(arg->class_path, class_name))
		return -1;

	if (jvm_stack_init() == -1)
		return -1;

	if (jvm_interp_env_init() == -1)
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
	printf("\njvm found method main().\n\n");

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

	while ((c = getopt(argc, argv, "p:s:v")) != -1) {
		switch (c) {
		case 'p':
			memset(jvm_arg->class_path, '\0', 1024);
			strcpy(jvm_arg->class_path, optarg);
			break;
		case 's':
			jvm_arg->print_class = 1;
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

	//print_jvm_arg();

	if (jvm_arg->print_class) {
		show_jvm_class(jvm_arg);
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
