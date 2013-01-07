/*
 * classreader.c - jvm class file parser.
 *
 * (c) wzt 2012, 2013         http://www.cloud-sec.org
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <assert.h>

#include "jvm.h"
#include "type.h"
#include "list.h"
#include "log.h"
#include "vm_error.h"

static int class_fd;
static int class_file_len;
static void *class_start_mem;
static char *p_mem;

int mmap_class_file(const char *class_file)
{
        struct stat f_stat;

        class_fd = open(class_file, O_RDONLY);
        if (class_fd == -1) {
                __error("open %s failed.", class_file);
                return -1;
        }

        if (stat(class_file, &f_stat) == -1) {
		__error("stat failed.");
                close(class_fd);
                return -1;
        }

        class_file_len = f_stat.st_size;
        __debug2("%s file len: %d\n", class_file, class_file_len);

        class_start_mem = mmap(NULL, class_file_len, PROT_READ, MAP_PRIVATE, class_fd, 0);
        if (!class_start_mem) {
		__error("mmap failed."); 
		close(class_fd);
                return -1;
        }
        __debug2("mmap %s at %p\n", class_file, class_start_mem);

        return 0;
}

int mmap_exit(void)
{
        if (munmap(class_start_mem, class_file_len) == -1) {
                __error("munmap failed.");
                return -1;
        }

        close(class_fd);
        return 0;
}

void show_class_info(char *fmt, ...)
{
	va_list arg;
	char buf[256];

	va_start(arg, fmt);
	vsprintf(buf, fmt, arg);
	va_end(arg);

	if (jvm_arg->print_class) {
		printf("%s", buf);
	}
	else {
		__debug2("%s", buf);
	}
}

int parse_class_magic(CLASS *jvm_class)
{
        /* read class magic number. */
        CLASS_READ_U4(jvm_class->class_magic, p_mem)

        show_class_info("magic: 0x%x\n", jvm_class->class_magic);
        if (jvm_class->class_magic != JVM_CLASS_MAGIC) {
                jvm_error(VM_ERROR_CLASS_FILE, "JVM class magic not match.\n");
                return -1;
        }
        show_class_info("jvm class magic match: 0x%x\n", jvm_class->class_magic);
        return 0;
}

int parse_class_version(CLASS *jvm_class)
{
        /* read class minor_version. */
        CLASS_READ_U2(jvm_class->minor_version, p_mem)
        show_class_info("jvm class minor_version: %d\n", jvm_class->minor_version);

        /* read class major_version. */
        CLASS_READ_U2(jvm_class->major_version, p_mem)
        show_class_info("jvm class major_version: %d\n", jvm_class->major_version);

	if (jvm_class->major_version < 45 || jvm_class->major_version > 50) {
		char err_buf[128];

		snprintf(err_buf, 1024, "JVM version error: %d.%d\n",
			jvm_class->major_version, jvm_class->minor_version);
		jvm_error(VM_ERROR_CLASS_FILE, err_buf);

		return -1;
	}

        return 0;
}

int handle_class_info(CLASS *jvm_class, u2 constant_pool_count, u2 idx)
{
	struct CONSTANT_Class_info *class_info;

        class_info = (struct CONSTANT_Class_info *)
			malloc(sizeof(struct CONSTANT_Class_info));
        if (!class_info) {
        	jvm_error(VM_ERROR_MEMORY, "Malloc failed.");
                return -1;
        }

        CLASS_READ_U2(class_info->name_index, p_mem);
        if (class_info->name_index < 0 || class_info->name_index >= constant_pool_count) {
		char err_buf[128];
		
		snprintf(err_buf, 128, "JVM class_info->name_index error: %d\n", 
			class_info->name_index);
		jvm_error(VM_ERROR_CLASS_FILE, err_buf);
		return -1;
	}
        show_class_info("name_index: %d\n", class_info->name_index);

        class_info->base = jvm_class->constant_info[class_info->name_index].base;

        jvm_class->constant_info[idx].index = idx;
        jvm_class->constant_info[idx].base = (u1 *)class_info;

	return 0;
}

int handle_class_InvokeDynamic(CLASS *jvm_class, u2 idx)
{
	struct CONSTANT_InvokeDynamic_info *invoke_dyc_info;

	invoke_dyc_info = (struct CONSTANT_InvokeDynamic_info *)
			malloc(sizeof(struct CONSTANT_InvokeDynamic_info));
	if (!invoke_dyc_info) {
		jvm_error(VM_ERROR_MEMORY, "Malloc failed.");
		return -1;
	}

        CLASS_READ_U2(invoke_dyc_info->bootstrap_method_attr_index, p_mem);
        CLASS_READ_U2(invoke_dyc_info->name_and_type_index, p_mem);
        show_class_info("bootstrap_method_attr_index: %d, name_and_type_index: %d\n",
        	invoke_dyc_info->bootstrap_method_attr_index,
                invoke_dyc_info->name_and_type_index);

        jvm_class->constant_info[idx].index = idx;
        jvm_class->constant_info[idx].base = (u1 *)invoke_dyc_info;

	return 0;
}

int handle_class_utf8(CLASS *jvm_class, u2 idx)
{
	u2 len;
        u1 *buf;

        CLASS_READ_U2(len, p_mem);
        buf = (u1 *)malloc(len + 1);
	if (!buf) {
		jvm_error(VM_ERROR_MEMORY, "Malloc failed.\n");
		return -1;
	}
	memset(buf, '\0', len + 1);

        memcpy(buf, p_mem, len);
        show_class_info("len: %d\t%s\n", len, buf);
        p_mem += len;

        jvm_class->constant_info[idx].index = idx;
        jvm_class->constant_info[idx].base = buf;

	return 0;
}

int handle_class_method_type(CLASS *jvm_class, u2 idx)
{
	struct CONSTANT_MethodType_info *method_type_info;

	method_type_info = (struct CONSTANT_MethodType_info *)
			malloc(sizeof(struct CONSTANT_MethodType_info));
	if (!method_type_info) {
		jvm_error(VM_ERROR_MEMORY, "Malloc failed.");
		return -1;
	}
        
        CLASS_READ_U2(method_type_info->descriptor_index, p_mem);
        show_class_info("descriptor_index %d\n", method_type_info->descriptor_index);

        jvm_class->constant_info[idx].index = idx;
        jvm_class->constant_info[idx].base = (u1 *)method_type_info;

	return 0;
}

int handle_class_method_handle(CLASS *jvm_class, u2 idx)
{
        struct CONSTANT_MethodHandle_info *method_handle_info;

        method_handle_info = (struct CONSTANT_MethodHandle_info *)
                        malloc(sizeof(struct CONSTANT_MethodHandle_info));
        if (!method_handle_info) {
                jvm_error(VM_ERROR_MEMORY, "malloc failed.");
                return -1;
        }

        CLASS_READ_U1(method_handle_info->reference_kind, p_mem);
        CLASS_READ_U2(method_handle_info->reference_index, p_mem);
        show_class_info("reference_kind: %d, reference_index: %d\n",
        	method_handle_info->reference_kind,
                method_handle_info->reference_index);

        jvm_class->constant_info[idx].index = idx;
        jvm_class->constant_info[idx].base = (u1 *)method_handle_info;

	return 0;
}

int handle_class_name_and_type(CLASS *jvm_class, u2 idx)
{
        struct CONSTANT_NameAndType_info *name_type_info;

        name_type_info = (struct CONSTANT_NameAndType_info *)
                        malloc(sizeof(struct CONSTANT_NameAndType_info));
        if (!name_type_info) {
                jvm_error(VM_ERROR_MEMORY, "Malloc failed.");
                return -1;
        }

        CLASS_READ_U2(name_type_info->name_index, p_mem);
        CLASS_READ_U2(name_type_info->descriptor_index, p_mem);
        show_class_info("name_index: %d, descriptor_index: %d\n",
        	name_type_info->name_index, name_type_info->descriptor_index);

        jvm_class->constant_info[idx].index = idx;
        jvm_class->constant_info[idx].base = (u1 *)name_type_info;

	return 0;
}

int handle_class_double(CLASS *jvm_class, u2 idx)
{
        struct CONSTANT_Double_info *double_info;

        double_info = (struct CONSTANT_Double_info *)
                        malloc(sizeof(struct CONSTANT_Double_info));
        if (!double_info) {
                jvm_error(VM_ERROR_MEMORY, "malloc failed.");
                return -1;
        }

        CLASS_READ_U4(double_info->high_bytes, p_mem);
        CLASS_READ_U4(double_info->low_bytes, p_mem);
        show_class_info("high_bytes: %d, low_bytes: %d\n",
                double_info->high_bytes, double_info->low_bytes);

        jvm_class->constant_info[idx].index = idx;
        jvm_class->constant_info[idx].base = (u1 *)double_info;

	return 0;
}

int handle_class_float(CLASS *jvm_class, u2 idx)
{
        struct CONSTANT_Float_info *float_info;

        float_info = (struct CONSTANT_Float_info *)
                        malloc(sizeof(struct CONSTANT_Float_info));
        if (!float_info) {
                jvm_error(VM_ERROR_MEMORY, "Malloc failed.");
                return -1;
        }

        CLASS_READ_U4(float_info->bytes, p_mem);
        show_class_info("bytes: %d\n", float_info->bytes);

        jvm_class->constant_info[idx].index = idx;
        jvm_class->constant_info[idx].base = (u1 *)float_info;

	return 0;
}

int handle_class_integer(CLASS *jvm_class, u2 idx)
{
        struct CONSTANT_Integer_info *integer_info;

        integer_info = (struct CONSTANT_Integer_info *)
                        malloc(sizeof(struct CONSTANT_Integer_info));
        if (!integer_info) {
                jvm_error(VM_ERROR_MEMORY, "Malloc failed.");
                return -1;
        }

        CLASS_READ_U4(integer_info->bytes, p_mem);
        show_class_info("bytes: %d\n", integer_info->bytes);

        jvm_class->constant_info[idx].index = idx;
        jvm_class->constant_info[idx].base = (u1 *)integer_info;

	return 0;
}

int handle_class_long(CLASS *jvm_class, u2 idx)
{
        struct CONSTANT_Long_info *long_info;

        long_info = (struct CONSTANT_Long_info *)
                        malloc(sizeof(struct CONSTANT_Long_info));
        if (!long_info) {
                jvm_error(VM_ERROR_MEMORY, "malloc failed.");
                return -1;
        }

        CLASS_READ_U2(long_info->high_bytes, p_mem);
        CLASS_READ_U2(long_info->low_bytes, p_mem);

        show_class_info("high bytes: %d, low bytes: %d\n",
        	long_info->high_bytes, long_info->low_bytes);

        jvm_class->constant_info[idx].index = idx;
        jvm_class->constant_info[idx].base = (u1 *)long_info;

	return 0;
}

int hanlde_class_string(CLASS *jvm_class, u2 constant_pool_count, u2 idx)
{
        struct CONSTANT_String_info *string_info;

        string_info = (struct CONSTANT_String_info *)
                        malloc(sizeof(struct CONSTANT_String_info));
        if (!string_info) {
                jvm_error(VM_ERROR_MEMORY, "malloc failed.");
                return -1;
        }

        CLASS_READ_U2(string_info->string_index, p_mem);
        if (string_info->string_index < 1 ||
                string_info->string_index >= constant_pool_count) {
		jvm_error(VM_ERROR_CLASS_FILE, "JVM string_index error.");
		return -1;
	}

        show_class_info("string index: %d\n", string_info->string_index);

	jvm_class->constant_info[idx].index = idx;
	jvm_class->constant_info[idx].base = (u1 *)string_info;
	return 0;
}

int handle_class_methodref_info(CLASS *jvm_class, u2 constant_pool_count, u2 idx)
{
        struct CONSTANT_Methodref_info *methodref_info;

        methodref_info = (struct CONSTANT_Methodref_info *)
                        malloc(sizeof(struct CONSTANT_Methodref_info));
        if (!methodref_info) {
                jvm_error(VM_ERROR_MEMORY, "malloc failed.");
                return -1;
        }

        CLASS_READ_U2(methodref_info->class_index, p_mem);
        if (methodref_info->class_index < 1 || 
                 methodref_info->class_index >= constant_pool_count) {
		jvm_error(VM_ERROR_CLASS_FILE, "JVM string_index error.");
		return -1;
	}

        CLASS_READ_U2(methodref_info->name_and_type_index, p_mem);
        if (methodref_info->class_index < 1 &&
                 methodref_info->class_index >= constant_pool_count) {
		jvm_error(VM_ERROR_CLASS_FILE, "JVM string_index error.");
		return -1;
	}
        show_class_info("class_index: %d, name_and_type_index: %d\n",
                 methodref_info->class_index,
                 methodref_info->name_and_type_index);

	jvm_class->constant_info[idx].index = idx;
	jvm_class->constant_info[idx].base = (u1 *)methodref_info;

	return 0;
}

int parse_class_constant(CLASS *jvm_class)
{
        u1 constant_tag;
        u2 idx;

        show_class_info("\n-----------parse contant pool count----------------------:\n\n");
        /* read constant_pool_count */
        CLASS_READ_U2(jvm_class->constant_pool_count, p_mem)
        show_class_info("jvm constant_pool_count: %d\n", jvm_class->constant_pool_count);

	if (jvm_class->constant_pool_count >= 65535) {
		jvm_error(VM_ERROR_CLASS_FILE, "JVM constant_pool_count too bigger.\n");
		return -1;
	}

        jvm_class->constant_info = (struct constant_info_st *)
			malloc(sizeof(struct constant_info_st) * jvm_class->constant_pool_count);
        if (!jvm_class->constant_info) {
                __error("Malloc failed.\n");
                return -1;
        }
	memset(jvm_class->constant_info, '\0', sizeof(struct constant_info_st) * 
		jvm_class->constant_pool_count);
		
	/* The constant_pool table is indexed from 1 to constant_pool_count-1. */
        for (idx = 1; idx <= jvm_class->constant_pool_count - 1; idx++ ) {
                CLASS_READ_U1(constant_tag, p_mem)
                show_class_info("- idx: %d constant tag: %d\t", idx, (int)constant_tag);
                switch (constant_tag) {
                case CONSTANT_Fieldref:
                case CONSTANT_Methodref:
                case CONSTANT_InterfaceMethodref:
			if (handle_class_methodref_info(jvm_class, jvm_class->constant_pool_count, 
				idx) == -1)
				return -1;
                        break;
                case CONSTANT_Class:
			if (handle_class_info(jvm_class, jvm_class->constant_pool_count, idx) == -1)
				return -1;
                        break;
                case CONSTANT_String:
			if (hanlde_class_string(jvm_class, jvm_class->constant_pool_count, idx) == -1)
				return -1;
                        break;
                case CONSTANT_Long:
			if (handle_class_long(jvm_class, idx) == -1)
				return -1;
                        break;
                case CONSTANT_Integer:
			if (handle_class_integer(jvm_class, idx) == -1)
				return -1;
                        break;
                case CONSTANT_Float:
			if (handle_class_float(jvm_class, idx) == -1)
				return -1;
                        break;
                case CONSTANT_Double:
			if (handle_class_double(jvm_class, idx) == -1)
				return -1;
                        break;
                case CONSTANT_NameAndType:
			if (handle_class_name_and_type(jvm_class, idx) == -1)
				return -1;
                        break;
                case CONSTANT_MethodHandle:
			if (handle_class_method_handle(jvm_class, idx) == -1)
				return -1;
                        break;
                case CONSTANT_MethodType:
			if (handle_class_method_type(jvm_class, idx) == -1)
				return -1;
                        break;
                case CONSTANT_InvokeDynamic:
			if (handle_class_InvokeDynamic(jvm_class, idx) == -1)
				return -1;
                        break;
                case CONSTANT_Utf8:
			if (handle_class_utf8(jvm_class, idx) == -1)
				return -1;
                        break;
                default:
			jvm_error(VM_ERROR_CLASS_FILE, "constant error.");
			return -1;
                }
        }
	show_class_info("\n");

        return 0;

out:
        mmap_exit();
        return -1;
}

int parse_class_access_flag(CLASS *jvm_class)
{
        /* read class access flag. */
        CLASS_READ_U2(jvm_class->access_flag, p_mem)
        show_class_info("class access_flag: 0x%x\n", jvm_class->access_flag);

/*
	if (jvm_class->access_flag != ACC_PUBLIC ||
		jvm_class->access_flag != ACC_FINAL ||
		jvm_class->access_flag != ACC_SUPER ||
		jvm_class->access_flag != ACC_INTERFACE ||
		jvm_class->access_flag != ACC_ABSTRACT ||
		jvm_class->access_flag != ACC_SYNTHETIC ||
		jvm_class->access_flag != ACC_ANNOTATION ||
		jvm_class->access_flag != ACC_ENUM) {
		jvm_error(VM_ERROR_CLASS_FILE, "JVM class wrong access_flag.");
		return -1;
	}
*/
	
        return 0;
}
int parse_class_this_super(CLASS *jvm_class)
{
        CLASS_READ_U2(jvm_class->this_class, p_mem)
        CLASS_READ_U2(jvm_class->super_class, p_mem)
        show_class_info("this_class: %d\tsuper_class: %d\n\n", jvm_class->this_class, 
		jvm_class->super_class);

        if (jvm_class->this_class < 1 &&
                jvm_class->this_class >= jvm_class->constant_pool_count) {
		jvm_error(VM_ERROR_CLASS_FILE, "JVM string_index error.");
		return -1;
	}

        if (jvm_class->super_class < 1 &&
                jvm_class->super_class >= jvm_class->constant_pool_count) {
		jvm_error(VM_ERROR_CLASS_FILE, "JVM string_index error.");
		return -1;
	}

        return 0;
}

int parse_class_interface(CLASS *jvm_class)
{
        u2 idx, index;

        CLASS_READ_U2(jvm_class->interfaces_count, p_mem)
        show_class_info("interfaces_count: %d\n", jvm_class->interfaces_count);

        for (idx = 0; idx < jvm_class->interfaces_count; idx++ ) {
                CLASS_READ_U2(index, p_mem);
                show_class_info("index: %d\n", index);
        }

        return 0;
}

int parse_class_filed(CLASS *jvm_class)
{
	u2 name_index;
        u2 idx, count;

	INIT_LIST_HEAD(&(jvm_class->filed_list_head));

	show_class_info("---------------parse class filed--------------------------:\n");
        CLASS_READ_U2(jvm_class->fileds_count, p_mem)
        show_class_info("filed_count: %d\n", jvm_class->fileds_count);

	for (idx = 0; idx < jvm_class->fileds_count; idx++) {
		CLASS_FILED *new_filed;

		new_filed = (CLASS_FILED *)malloc(sizeof(CLASS_FILED));
		if (!new_filed) {
			__error("malloc failed.");
			return -1;
		}

        	CLASS_READ_U2(new_filed->access_flag, p_mem)
        	show_class_info("\naccess_flag: 0x%x\n", new_filed->access_flag);

        	CLASS_READ_U2(new_filed->name_index, p_mem)
        	show_class_info("name_index: 0x%x\n", new_filed->name_index);

        	CLASS_READ_U2(new_filed->descriptor_index, p_mem)
        	show_class_info("descriptor_index: 0x%x\n", new_filed->descriptor_index);

        	CLASS_READ_U2(new_filed->attributes_count, p_mem)
        	show_class_info("attributes_count: 0x%x\n", new_filed->attributes_count);

                /* parse attributes */
		for (count = 0; count < new_filed->attributes_count; count++) {
                	CLASS_READ_U2(name_index, p_mem)
                	show_class_info("attritbutes name_index: %d\n", name_index);

                	if (!strcmp(jvm_class->constant_info[name_index].base, "ConstantValue")) {
                        	show_class_info("parse ConstantValue attribute:\n");
                	}
                	if (!strcmp(jvm_class->constant_info[name_index].base, "Signature")) {
                        	show_class_info("parse Signature:\n");
                	}
		}
		
		new_filed->name_base = jvm_class->constant_info[new_filed->name_index].base;
		new_filed->desc_base = jvm_class->constant_info[new_filed->descriptor_index].base;
		new_filed->class = jvm_class;
		show_class_info("#%s\t%s\n", new_filed->name_base, new_filed->desc_base);
		list_add_tail(&(new_filed->list), &(jvm_class->filed_list_head));
	}

        return 0;
}

int __parse_exception_table(CLASS_CODE *code, u4 len)
{
	EXCEPTION_TABLE *exception_table;
        u2 idx;

	exception_table = (EXCEPTION_TABLE *)malloc(sizeof(EXCEPTION_TABLE) * len);
	if (!exception_table) {
		__error("malloc failed.");
		return -1;
	}

        for (idx = 0; idx < len; idx++ ) {
                CLASS_READ_U2(exception_table[idx].start_pc, p_mem)
                show_class_info("start_pc: %d\n", exception_table[idx].start_pc);

                CLASS_READ_U2(exception_table[idx].end_pc, p_mem)
                show_class_info("end_pc: %d\n", exception_table[idx].end_pc);

                CLASS_READ_U2(exception_table[idx].handler_pc, p_mem)
                show_class_info("handler_pc: %d\n", exception_table[idx].handler_pc);

                CLASS_READ_U2(exception_table[idx].catch_type, p_mem)
                show_class_info("catch_type: %d\n", exception_table[idx].catch_type);
        }

	code->exception_table = exception_table;
        return 0;
}

void print_line_number_table(LINE_NUMBER_TABLE_ATTR *table_attr)
{
	u2 idx;

	show_class_info("\nLineNumberTable:\n");
	for (idx = 0; idx < table_attr->line_number_table_length; idx++) {
		show_class_info("line: %d : %d\n", 
			table_attr->table_base[idx].start_pc,
			table_attr->table_base[idx].line_number);
	}
}

int __parse_line_number_table(CLASS_CODE *code, int index)
{
	LINE_NUMBER_TABLE_ATTR *table_attr;
        u2 idx;

	table_attr = (LINE_NUMBER_TABLE_ATTR *)malloc(sizeof(LINE_NUMBER_TABLE_ATTR));
	if (!table_attr) {
		__error("malloc failed.");
		return -1;
	}

        CLASS_READ_U4(table_attr->attribute_length, p_mem)
        show_class_info("\t\tattribute_length: %d\n", table_attr->attribute_length);

        CLASS_READ_U2(table_attr->line_number_table_length, p_mem)
        show_class_info("\t\tline_number_table_length: %d\n", 
		table_attr->line_number_table_length);

	table_attr->table_base = (LINE_NUMBER_TABLE *)
		malloc(sizeof(LINE_NUMBER_TABLE) * table_attr->line_number_table_length);
	if (!table_attr->table_base) {
		free(table_attr);
		return -1;
	}

        for (idx = 0; idx < table_attr->line_number_table_length; idx++ ) {
                CLASS_READ_U2((table_attr->table_base)[idx].start_pc, p_mem)
                show_class_info("\t\tstart_pc: %d\n", (table_attr->table_base)[idx].start_pc);

                CLASS_READ_U2(table_attr->table_base[idx].line_number, p_mem)
                show_class_info("\t\tline_number: %d\n", table_attr->table_base[idx].line_number);
        }

	code->table_attr = table_attr;
        return 0;
}

int __parse_verification_type_info(union verification_type_info *ver_info)
{
        u1 tag;

        CLASS_READ_U1(tag, p_mem)
        show_class_info("\t\ttag: %d\n", tag);
        switch (tag) {
                case ITEM_Top:
                        show_class_info("\t\tITEM_Top.\n");
			ver_info->tag = tag;
                        break;
                case ITEM_Integer:
                        show_class_info("\t\tITEM_Integer.\n");
			ver_info->tag = tag;
                        break;
                case ITEM_Float:
                        show_class_info("\t\tITEM_float.\n");
			ver_info->tag = tag;
                        break;
                case ITEM_Double:
                        show_class_info("\t\tITEM_Double.\n");
			ver_info->tag = tag;
                        break;
                case ITEM_Long:
                        show_class_info("\t\tITEM_Long.\n");
			ver_info->tag = tag;
                        break;
                case ITEM_Null:
                        show_class_info("\t\tITEM_NULL.\n");
			ver_info->tag = tag;
                        break;
                case ITEM_UninitializedThis:
                        show_class_info("\t\tITEM_UninitializedThis.\n");
			ver_info->tag = tag;
                        break;
                case ITEM_Object:
                {
                        show_class_info("\t\tITEM_Object.\n");
			ver_info->tag = tag;
                        CLASS_READ_U2(ver_info->a.cpool_index, p_mem)
                        show_class_info("\t\tcpool_index: %d\n", ver_info->a.cpool_index);
                        break;
                }
                case ITEM_Uninitialized:
                {
                        show_class_info("\t\tITEM_Uninitialized.\n");
			ver_info->tag = tag;
                        CLASS_READ_U2(ver_info->b.offset, p_mem)
                        show_class_info("\t\toffset: %d\n", ver_info->b.offset);
                        break;
                }
                default:
                        return -1;
        }

        return 0;
}

union verification_type_info *parse_ver_info(u1 stack_num)
{
        union verification_type_info *ver_info;
	u1 idx;

        ver_info = (union verification_type_info *)malloc(
                sizeof(union verification_type_info) * stack_num);
        if (!ver_info) {
                __error("malloc failed.");
                return NULL;
        }

        for (idx = 0; idx < stack_num; idx++) {
		if (__parse_verification_type_info(ver_info + idx) == -1) {
			goto out;
        	}
	}

	return ver_info;

out:
	for (; idx > 0; idx--)
		free(ver_info + idx);
	return NULL;
}

int __parse_stack_map_frame(STACK_MAP_FRAME *stack_frame)
{
	u1 frame_type;
	u1 idx;

	CLASS_READ_U1(frame_type, p_mem)
        show_class_info("\t\tframe_type: %d\n", frame_type);
	stack_frame->frame_type = frame_type;

        if (frame_type <= 63) {
        	stack_frame->offset_delta = frame_type;
                show_class_info("\t\tsame_frame\toffset_delta: %d\n", stack_frame->offset_delta);
        }
        if (frame_type >= 64 && frame_type <= 127) {
		union verification_type_info *ver_info;

        	stack_frame->offset_delta = frame_type - 64;
                stack_frame->stack_num = 1;
                show_class_info("\t\tsame_locals_l_stack_item_frame\toffset_delta: %d\n",
                	stack_frame->offset_delta);

		ver_info = parse_ver_info(stack_frame->stack_num);
		if (!ver_info)
			return -1;
		stack_frame->b.ver_info = ver_info;
        }
        if (frame_type == 247) {
		union verification_type_info *ver_info;

                stack_frame->stack_num = 1;
                CLASS_READ_U2(stack_frame->offset_delta, p_mem)
                show_class_info("\t\tsame_locals_l_stack_item_frame_extended\toffset_delta: %d\n",
                        stack_frame->offset_delta);
                ver_info = parse_ver_info(stack_frame->stack_num);
                if (!ver_info)
                        return -1;

                stack_frame->c.ver_info = ver_info;
		
        }
        if (frame_type >= 248 && frame_type <= 250) {
                CLASS_READ_U2(stack_frame->offset_delta, p_mem)
                show_class_info("\t\tchop_frame\toffset_delta: %d\n", stack_frame->offset_delta);
        }
        if (frame_type == 251) {
                CLASS_READ_U2(stack_frame->offset_delta, p_mem)
                show_class_info("\t\tsame_frame_extended\toffset_delta: %d\n", 
			stack_frame->offset_delta);
        }
        if (frame_type >= 252 && frame_type <= 254) {
		union verification_type_info *ver_info;

                CLASS_READ_U2(stack_frame->offset_delta, p_mem)
                show_class_info("\t\tappend_frame\toffset_delta: %d\n", stack_frame->offset_delta);

                stack_frame->locals_num = frame_type - 251;
                show_class_info("\t\tlocals_num: %d\n", stack_frame->locals_num);
                ver_info = parse_ver_info(stack_frame->stack_num);
                if (!ver_info)
                        return -1;

                stack_frame->f.ver_info = ver_info;
        }
}

int __parse_stack_map_table(CLASS_CODE *code, u2 index)
{
	STACK_MAP_ATTR *stack_map;
        u2 idx;

	stack_map = (STACK_MAP_ATTR *)malloc(sizeof(STACK_MAP_ATTR));
	if (!stack_map) {
		__error("malloc failed.");
		return -1;
	}

	stack_map->attribute_name_index = index;

        CLASS_READ_U4(stack_map->attribute_length, p_mem)
        show_class_info("\t\tattribute_length: %d\n", stack_map->attribute_length);

        CLASS_READ_U2(stack_map->number_of_entries, p_mem)
        show_class_info("\t\tnumber_of_entries: %d\n", stack_map->number_of_entries);

	stack_map->stack_frame = (STACK_MAP_FRAME *)malloc(
		sizeof(STACK_MAP_FRAME) * stack_map->number_of_entries);
	if (!stack_map->stack_frame) {
		__error("malloc failed.");
		return -1;
	}

	for (idx = 0; idx < stack_map->number_of_entries; idx++) {
       		if (__parse_stack_map_frame(stack_map->stack_frame + idx) == -1) {
			goto out;
		}
	}

	code->stack_map_attr = stack_map;
        return 0;

out:
	for (; idx > 0; idx--)
		free(stack_map->stack_frame + idx);
	free(stack_map);
	return -1;
}

void print_stack_map(STACK_MAP_ATTR *stack_map)
{
	u1 frame_type;
	u2 idx;

	show_class_info("\nStackMapTable: number of entries: %d\n", 
		stack_map->number_of_entries);
	for (idx = 0; idx < stack_map->number_of_entries; idx++) {
		frame_type = (stack_map->stack_frame + idx)->frame_type;
	        if (frame_type <= 63) {
                	show_class_info("frame_type: %d\tsame_frame\toffset_delta: %d\n", 
				frame_type, (stack_map->stack_frame + idx)->offset_delta);
        	}
        	if (frame_type >= 64 && frame_type <= 127) {
                	show_class_info("frame_type: %d\tsame_locals_l_stack_item_frame\t"
				"offset_delta: %d\n",
                        	frame_type, (stack_map->stack_frame + idx)->offset_delta);
		}
        	if (frame_type == 247) {
                	show_class_info("frame_type: %d\tsame_locals_l_stack_item_frame_extended\t"
				"offset_delta: %d\n",
                        	frame_type, (stack_map->stack_frame + idx)->offset_delta);
		}
        	if (frame_type >= 248 && frame_type <= 250) {
                	show_class_info("frame_type: %d\tchop_frame\toffset_delta: %d\n", 
				frame_type, (stack_map->stack_frame + idx)->offset_delta);
        	}
        	if (frame_type == 251) {
                	show_class_info("frame_type: %d\tsame_frame_extended\toffset_delta: %d\n",
                        	frame_type, (stack_map->stack_frame + idx)->offset_delta);
        	}
        	if (frame_type >= 252 && frame_type <= 254) {
			show_class_info("frame_type: %d\tappend_frame\toffset_delta: %d\n", 
				frame_type, (stack_map->stack_frame + idx)->offset_delta);
		}
	}
}

int add_opcode(CLASS_CODE *code)
{
        CLASS_READ_U4(code->code_length, p_mem)
        show_class_info("\tcode_length: %d\n", code->code_length);

        code->code = (u1 *)malloc(code->code_length + 1);
        if (!code->code) {
                __error("Malloc failed.");
                return -1;
        }
        memcpy(code->code, p_mem, code->code_length);
        code->code[code->code_length] = '\0';
        p_mem += code->code_length;

	return 0;
}

int init_method_stack(CLASS_CODE *code)
{
	int stack_size = 0;
	char *stack_base;

	stack_size = (int)code->max_stack * sizeof(int) + 
			(int)code->max_locals * sizeof(int);
	stack_base = (char *)malloc(stack_size);
	if (!stack_base) {
		__error("malloc failed.");
		return -1;
	}
	memset(stack_base, '\0', stack_size);
	
	code->stack_frame.local_var_table = (u1 *)stack_base;
	code->stack_frame.operand_stack = 
			(u1 *)(stack_base + (int)code->max_locals * sizeof(int));
	code->stack_frame.method = code->method;
	code->stack_frame.return_addr = NULL;
	code->stack_frame.offset = 0;
	code->stack_frame.max_stack = code->max_stack;
	code->stack_frame.max_locals = code->max_locals;
	code->stack_frame.prev_stack = NULL;

	show_class_info("#stack size: %d\t#local: 0x%x\tstack: 0x%x\n", stack_size,
		code->stack_frame.local_var_table, code->stack_frame.operand_stack);
	
	return 0;
}

/* attribute_name_index has been parsed before. */
int parse_code_attribute(CLASS *jvm_class, CLASS_METHOD *method, u2 name_index)
{
	CLASS_CODE *code;
	u2 attribute_name_index;
        u2 idx;

	code = (CLASS_CODE *)malloc(sizeof(CLASS_CODE));
	if (!code) {
		__error("malloc failed.");
		return -1;
	}
	memset(code, '\0', sizeof(CLASS_CODE));

	code->attribute_name_index = name_index;
	code->method = (u4 *)method;

        CLASS_READ_U4(code->attribute_length, p_mem)
        show_class_info("\tattribute_length: %d\n", code->attribute_length);

        CLASS_READ_U2(code->max_stack, p_mem)
        show_class_info("\tmax_stack: %d\n", code->max_stack);

        CLASS_READ_U2(code->max_locals, p_mem)
        show_class_info("\tmax_locals: %d\n", code->max_locals);

	if (add_opcode(code) == -1)
		return -1;

	if (init_method_stack(code) == -1)
		return -1;

        CLASS_READ_U2(code->exception_table_length, p_mem)
        show_class_info("\texception_table_length: %d\n", code->exception_table_length);
        if (__parse_exception_table(code, code->exception_table_length) == -1)
		return -1;

        CLASS_READ_U2(code->attributes_count, p_mem)
        show_class_info("\tattributes_count: %d\n", code->attributes_count);

        /* parse attributes */
        for (idx = 0; idx < code->attributes_count; idx++ ) {
                CLASS_READ_U2(attribute_name_index, p_mem)
                show_class_info("\tidx: %d attribute_name_index: %d", idx + 1, attribute_name_index);

                if (!strcmp(jvm_class->constant_info[attribute_name_index].base, "LineNumberTable")) {
                        show_class_info("\n\tparse LineNumberTable:\n");
                        if (__parse_line_number_table(code, attribute_name_index) == -1)
				return -1;
                }
                if (!strcmp(jvm_class->constant_info[attribute_name_index].base, "StackMapTable")) {
                        show_class_info("\n\tparse StackMapTable:\n");
                        if (__parse_stack_map_table(code, attribute_name_index) == -1)
				return -1;
                }
                if (!strcmp(jvm_class->constant_info[attribute_name_index].base, "LocalVariableTable")) {
                        ;
                }
                if (!strcmp(jvm_class->constant_info[attribute_name_index].base, "LocalVariableTypeTable")) {
                        ;
                }
        }

	method->code_attr = code;
        return 0;
}

int parse_exception_attribute(CLASS_METHOD *method, u2 index)
{
	CLASS_EXCEPTION *exception;
	u2 idx;

	exception = (CLASS_EXCEPTION *)malloc(sizeof(CLASS_EXCEPTION));
	if (!exception) {
		__error("malloc failed.");
		return -1;
	}
	exception->attribute_name_index = index;

        CLASS_READ_U4(exception->attribute_length, p_mem)
        show_class_info("\tattribute_length: %d\n", exception->attribute_length);
        CLASS_READ_U2(exception->number_of_exceptions, p_mem)
        show_class_info("\tnumber_of_exceptions: %d\n", exception->number_of_exceptions);

	exception->exception_index_table = 
		(u2 *)malloc(sizeof(u2) * exception->attribute_length);
	if (!exception->exception_index_table) {
		free(exception);
		return -1;
	}
	for (idx = 0; idx < exception->number_of_exceptions; idx++) {
		CLASS_READ_U2(exception->exception_index_table[idx], p_mem);
	}

	method->exception_attr = exception;
	return 0;
}

int parse_synthetic_attribute(CLASS_METHOD *method, u2 index)
{
	CLASS_SYNTHETIC *synthetic;

	synthetic = (CLASS_SYNTHETIC *)malloc(sizeof(CLASS_SYNTHETIC));
	if (!synthetic) {
		__error("malloc failed.");
		return -1;
	}

	synthetic->attribute_name_index = index;
        CLASS_READ_U4(synthetic->attribute_length, p_mem)
	show_class_info("\tattribute_length: %d\n", synthetic->attribute_length);

	method->synthetic = synthetic;
	return 0;
}

int parse_deprecated_attribute(CLASS_METHOD *method, u2 index)
{
        CLASS_DEPRECATED *deprecated;

        deprecated = (CLASS_DEPRECATED *)malloc(sizeof(CLASS_DEPRECATED));
        if (!deprecated) {
                __error("malloc failed.");
                return -1;
        }

        deprecated->attribute_name_index = index;
        CLASS_READ_U4(deprecated->attribute_length, p_mem)
        show_class_info("\tattribute_length: %d\n", deprecated->attribute_length);

        method->deprecated = deprecated;
        return 0;
}

int parse_class_method(CLASS *jvm_class)
{
	u2 name_index;
        u2 idx, count;

	INIT_LIST_HEAD(&(jvm_class->method_list_head));

        show_class_info("\n---------------parse class method-------------------------:\n\n");
        CLASS_READ_U2(jvm_class->method_count, p_mem)
        show_class_info("method_count: %d\n", jvm_class->method_count);

        for (idx = 0; idx < jvm_class->method_count; idx++ ) {
		CLASS_METHOD *new_method;

		show_class_info("\n--------%d-----------\n", idx);
		new_method = (CLASS_METHOD *)malloc(sizeof(CLASS_METHOD));
		if (!new_method) {
			__error("malloc failed.");
			return -1;
		}

                CLASS_READ_U2(new_method->access_flag, p_mem)
                show_class_info("access_flags: 0x%x\n", new_method->access_flag);

                CLASS_READ_U2(new_method->name_index, p_mem)
                show_class_info("name_index: %d\n", new_method->name_index);

                CLASS_READ_U2(new_method->descriptor_index, p_mem)
                show_class_info("descriptor_index: %d\n", new_method->descriptor_index);

                CLASS_READ_U2(new_method->attributes_count, p_mem)
                show_class_info("attributes_count: %d\n\n", new_method->attributes_count);

                /* parse attributes */
		for (count = 0; count < new_method->attributes_count; count++) {
                	CLASS_READ_U2(name_index, p_mem)
                	show_class_info("attritbutes name_index: %d\n", name_index);
			show_class_info("!%s\n", jvm_class->constant_info[name_index].base);

                	if (!strcmp(jvm_class->constant_info[name_index].base, "Code")) {
                        	show_class_info("parse code attribute:\n");
                        	if (parse_code_attribute(jvm_class, new_method, name_index) == -1)
					return -1;
                	}
			else if (!strcmp(jvm_class->constant_info[name_index].base, "Exceptions")) {
				show_class_info("parse Exceptions attribute:\n");
				if (parse_exception_attribute(new_method, name_index) == -1)
					return -1;
                	}
                	else if (!strcmp(jvm_class->constant_info[name_index].base, "Signature")) {
				show_class_info("parse Signature attribute:\n");
                	}
                	else if (!strcmp(jvm_class->constant_info[name_index].base, "Synthetic")) {
				show_class_info("parse Synthetic attribute:\n");
                        	if (parse_synthetic_attribute(new_method, name_index) == -1)
					return -1;
                	}
                	else if (!strcmp(jvm_class->constant_info[name_index].base, "Deprecated")) {
				show_class_info("parse Deprecated attribute:\n");
                        	if (parse_deprecated_attribute(new_method, name_index) == -1)
					return -1;
                	}
                	else if (!strcmp(jvm_class->constant_info[name_index].base, "Deprecated")) {
				show_class_info("parse Deprecated attribute:\n");
                	}
                	else if (!strcmp(jvm_class->constant_info[name_index].base, 
				"untimeVisibleAnnotations")) {
				show_class_info("parse untimeVisibleAnnotations attribute:\n");
                	}
                	else if (!strcmp(jvm_class->constant_info[name_index].base, 
				"RuntimeInvisibleAnnotations")) {
				show_class_info("parse RuntimeInvisibleAnnotations attribute:\n");
                	}
                	else if (!strcmp(jvm_class->constant_info[name_index].base, 
				"RuntimeVisibleParameterAnnotations")) {
				show_class_info("parse RuntimeVisibleParameterAnnotations attribute:\n");
                	}
                	else if (!strcmp(jvm_class->constant_info[name_index].base, 
				"RuntimeInVisibleParameterAnnotations")) {
				show_class_info("parse RuntimeInVisibleParameterAnnotations attribute:\n");
                	}
                	else if (!strcmp(jvm_class->constant_info[name_index].base, "AnnotationDefault")) {
				show_class_info("parse AnnotationDefault attribute:\n");
                	}
			else {
				show_class_info("error attribute.\n");
				return -1;
			}
		}
                new_method->name_base = jvm_class->constant_info[new_method->name_index].base;
                new_method->desc_base = jvm_class->constant_info[new_method->descriptor_index].base;
                show_class_info("#%s\t%s\n", new_method->name_base, new_method->desc_base);
		new_method->class = jvm_class;
                list_add_tail(&(new_method->list), &(jvm_class->method_list_head));
        }

        return 0;
}

CLASS_FILED *lookup_class_filed(struct list_head *list_head, char *class_name, 
		char *method_name)
{
	struct list_head *s, *q;
	CLASS *r;
	CLASS_FILED *p;

	list_for_each(q, list_head) {
		r = list_entry(q, CLASS, list);
		if (r && !strcmp(r->class_file, class_name)) {
			list_for_each(s, (&r->filed_list_head)) {
				p = list_entry(s, CLASS_FILED, list);
				if (p && !strcmp(p->name_base, method_name)) {
					//show_class_info("found method: %s\n", p->name_base);
					return p;
				}
			}
		}
	}
	
	return NULL;	
}

CLASS_FILED *__lookup_class_filed(struct list_head *list_head, char *method_name)
{
	struct list_head *s, *q;
	CLASS *r;
	CLASS_FILED *p;

	list_for_each(q, list_head) {
		r = list_entry(q, CLASS, list);
		if (r) {
			list_for_each(s, (&r->filed_list_head)) {
				p = list_entry(s, CLASS_FILED, list);
				if (p && !strcmp(p->name_base, method_name)) {
					//show_class_info("found method: %s\n", p->name_base);
					return p;
				}
			}
		}
	}
	
	return NULL;	
}

CLASS_METHOD *lookup_class_method(struct list_head *list_head, char *class_name, 
		char *method_name)
{
	struct list_head *s, *q;
	CLASS *r;
	CLASS_METHOD *p;

	list_for_each(q, list_head) {
		r = list_entry(q, CLASS, list);
		if (r && !strcmp(r->class_file, class_name)) {
			list_for_each(s, (&r->method_list_head)) {
				p = list_entry(s, CLASS_METHOD, list);
				if (p && !strcmp(p->name_base, method_name)) {
					//show_class_info("found method: %s\n", p->name_base);
					return p;
				}
			}
		}
	}
	
	return NULL;	
}

CLASS_METHOD *__lookup_class_method(struct list_head *list_head, char *method_name)
{
        struct list_head *s, *q;
        CLASS *r;
        CLASS_METHOD *p;

        list_for_each(q, list_head) {
                r = list_entry(q, CLASS, list);
                if (r) {
                        list_for_each(s, (&r->method_list_head)) {
                                p = list_entry(s, CLASS_METHOD, list);
                                if (p && !strcmp(p->name_base, method_name)) {
                                        //show_class_info("found method: %s\n", p->name_base);
                                        return p;
                                }
                        }
                }
        }

        return NULL;
}

int lookup_class_file(struct list_head *list_head, char *class_file)
{
	struct list_head *p;
	CLASS *s;

	list_for_each(p, list_head) {
		s = list_entry(p, CLASS, list);
		if (s && !strcmp(s->class_file, class_file))
			return 0;
	}

	return -1;
}

CLASS *jvm_parse_class_file(const char *class_file, const char *class_name)
{
	CLASS *new_class;

        assert(class_file != NULL);
        if (mmap_class_file(class_file) == -1)
                return NULL;

	new_class = (CLASS *)malloc(sizeof(CLASS));
	if (!new_class) {
		__error("malloc failed.");
		return NULL;
	}
	memset(new_class, '\0', sizeof(CLASS));

	strcpy(new_class->class_file, class_name);
	
        p_mem = class_start_mem;
        if (parse_class_magic(new_class) == -1)
                goto out;

        if (parse_class_version(new_class) == -1)
                goto out;

        if (parse_class_constant(new_class) == -1)
                goto out;

        if (parse_class_access_flag(new_class) == -1)
                goto out;

        if (parse_class_this_super(new_class) == -1)
                goto out;

        if (parse_class_interface(new_class) == -1)
                goto out;

        if (parse_class_filed(new_class) == -1)
                goto out;

        if (parse_class_method(new_class) == -1)
                goto out;

	list_add_tail(&(new_class->list), &jvm_class_list_head);
        mmap_exit();
        return new_class;
out:
	free(new_class);
	mmap_exit();
        return NULL;
}

CLASS *jvm_load_class(const char *class_path, const char *class_name)
{
	CLASS *class;
	struct dirent *dirent;
	struct stat f_stat;
	DIR *dir;
	char tmp_path[1024], tmp[1024];

	dir = opendir(class_path);
	if (!dir) {
		__error("opendir error.");
		return NULL;
	}
	
	snprintf(tmp, sizeof(tmp), "%s.class", class_name);
	while ((dirent = readdir(dir)) != NULL) {
		if (!strcmp(dirent->d_name, ".") || !strcmp(dirent->d_name, ".."))
			continue; 

		memset(tmp_path, '\0', 1024);
		snprintf(tmp_path, 1024, "%s/%s", class_path, dirent->d_name);
		//show_class_info("%s\n", dirent->d_name);
		if (stat(tmp_path, &f_stat) == -1) {
			__error("stat error.");
			closedir(dir);
			return NULL;
		}
		if (S_ISREG(f_stat.st_mode)) {
			if (!strcmp(dirent->d_name, tmp)) {
				show_class_info("found class file: %s\n", tmp);
				class = jvm_parse_class_file(tmp_path, class_name);
				if (!class) {
					closedir(dir);
					return NULL;
				}
				closedir(dir);
				return class;
			}
		}
		if (S_ISDIR(f_stat.st_mode)) {
			jvm_load_class(tmp_path, class_name);
		}
	}

	//show_class_info("not found class file: %s\n", tmp);
	closedir(dir);
	return NULL;
}

void init_class_parse(void)
{
}

void exit_class_parse(void)
{
	mmap_exit();
}
