#ifndef VM_ERROR_H
#define VM_ERROR_H

#define VM_ERROR_CLASS_FILE		0
#define VM_ERROR_MEMORY			1
#define VM_ERROR_INTERP			2

void jvm_warning(int flag, char *fmt, ...);
void jvm_error(int flag, char *fmt, ...);

#endif
