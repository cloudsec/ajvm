/*
 * vm_error.c (c) wzt 2012, 2013	http://www.cloud-sec.org
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jvm.h"
#include "log.h"
#include "trace.h"
#include "vm_error.h"

void jvm_error(int flag, char *msg)
{
	switch (flag) {
	case VM_ERROR_CLASS_FILE:
		__error("%s", msg);
		break;
	case VM_ERROR_MEMORY:
		__error("%s", msg);
		break;
	default:
		printf("VM Error: Unkown flag.\n");
		break;
	}

	calltrace();
	mmap_exit();
	calltrace_exit();
	exit(0);
}
