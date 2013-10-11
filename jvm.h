#ifndef JVM_H
#define JVM_H

#include "type.h"
#include "list.h"

#define VM_DEBUG

#define JVM_VERSION					0.02
#define JVM_BANNER					"(c) wzt 2012,2013"

#define JVM_CLASS_MAGIC                 		0xcafebabe

#define CLASS_READ_U4(s, p)     	                	\
	do {							\
        	s = (((*(u4 *)p >> 24) & 0x000000ff) |         	\
                	((*(u4 *)p >> 8) & 0x0000ff00) |       	\
                	((*(u4 *)p << 24) & 0xff000000) |      	\
                	((*(u4 *)p << 8) & 0x00ff0000));	\
		p += 4;						\
	} while (0);

#define CLASS_READ_U2(s, p)             	        	\
	do {							\
        	s = (((*(u2 *)p >> 8) & 0x00ff) |              	\
                	((*(u2 *)p << 8) & 0xff00));		\
		p += 2;						\
	} while (0);				

#define CLASS_READ_U1(s, p)             	        	\
	do {							\
        	s = *(u1 *)p;					\
		p += 1;						\
	} while (0);				

#define CLASS_READ_STRING(s, p, len)             		\
	do {							\
        	memcpy(s, p, len);				\
	} while (0);				

#define CONSTANT_Class					7
#define CONSTANT_Fieldref				9
#define CONSTANT_Methodref				10
#define CONSTANT_InterfaceMethodref			11
#define CONSTANT_String					8
#define CONSTANT_Integer				3
#define CONSTANT_Float					4
#define CONSTANT_Long					5
#define CONSTANT_Double					6
#define CONSTANT_NameAndType				12
#define CONSTANT_Utf8					1
#define CONSTANT_MethodHandle				15
#define CONSTANT_MethodType				16
#define CONSTANT_InvokeDynamic				18

#define ACC_PUBLIC					0x0001
#define ACC_FINAL					0x0010
#define ACC_SUPER					0x0020
#define ACC_INTERFACE					0x0200
#define ACC_ABSTRACT					0X0400
#define ACC_SYNTHETIC					0x1000
#define ACC_ANNOTATION					0x2000
#define ACC_ENUM					0x4000

// 0000 0000 0010 0000
#define IS_ACC_PUBLIC(x)				(x & ACC_PUBLIC)

#define METHOD_ACC_PUBLIC				0x0001
#define METHOD_ACC_PRIVATE				0x0002
#define METHOD_ACC_PROTECTED				0x0004
#define METHOD_ACC_STATIC				0x0008
#define METHOD_ACC_FINAL				0x0010
#define METHOD_ACC_SYNCHRONIED				0x0020
#define METHOD_ACC_BRIDGE				0x0040
#define METHOD_ACC_VARARGS				0x0080
#define METHOD_ACC_NATIVE				0x0100
#define METHOD_ACC_ABSTRACT				0x0400
#define METHOD_ACC_STRICT				0x0800
#define METHOD_ACC_SYNTHETIC				0x1000

#define ITEM_Top					0
#define ITEM_Integer					1
#define ITEM_Float					2
#define ITEM_Double					3
#define ITEM_Long					4
#define ITEM_Null					5
#define ITEM_UninitializedThis				6
#define ITEM_Object					7
#define ITEM_Uninitialized				8

#define ARG_BYTE					'B'
#define ARG_CHAR					'C'
#define ARG_DOUBLE					'D'
#define ARG_FLOAT					'F'
#define ARG_INT						'I'
#define ARG_LONG					'J'
#define ARG_REFERENCE					'L'
#define ARG_SHORT					'S'
#define ARG_BOOLEAN					'Z'
#define ARG_ARRAY					'['

typedef struct opcode_st {
	int len;
	char *base;
	struct list_head list;
}OPCODE;

struct constant_info_st {
	u2 index;
	u1 tag;
	u1 *base;
}__attribute__ ((packed));

struct CONSTANT_Class_info {
	u2 name_index;
	u1 *base;
}__attribute__ ((packed));

struct CONSTANT_Fieldref_info {
	u2 class_index;
	u2 name_and_type_index;
}__attribute__ ((packed));

struct CONSTANT_Methodref_info {
	u2 class_index;
	u2 name_and_type_index;
}__attribute__ ((packed));

struct CONSTANT_InterfaceMethodref_info {
	u2 class_index;
	u2 name_and_type_inex;
}__attribute__ ((packed));

struct CONSTANT_String_info {
	u2 string_index;
}__attribute__ ((packed));

struct CONSTANT_Integer_info {
	u4 bytes;
}__attribute__ ((packed));

struct CONSTANT_Float_info {
	u4 bytes;
}__attribute__ ((packed));

struct CONSTANT_Long_info {
	u4 high_bytes;
	u4 low_bytes;
}__attribute__ ((packed));

struct CONSTANT_Double_info {
	u4 high_bytes;
	u4 low_bytes;
}__attribute__ ((packed));

struct CONSTANT_NameAndType_info {
	u2 name_index;
	u2 descriptor_index;
}__attribute__ ((packed));

struct CONSTANT_Utf8_info {
	u2 length;
	u1 bytes[];
}__attribute__ ((packed));

struct CONSTANT_MethodHandle_info {
	u1 reference_kind;
	u2 reference_index;
}__attribute__ ((packed));

struct CONSTANT_MethodType_info {
	u2 descriptor_index;
}__attribute__ ((packed));

struct CONSTANT_InvokeDynamic_info {
	u2 bootstrap_method_attr_index;
	u4 name_and_type_index;
}__attribute__ ((packed));

struct jvm_class;

typedef struct filed_info {
	u2 access_flag;
	u2 name_index;
	u2 descriptor_index;
	u2 attributes_count;
	u1 *name_base;
	u1 *desc_base;
	struct list_head list;
	struct jvm_class *class;
	union {
		int value1;
		long value2;
	};
}CLASS_FILED;

typedef struct exception_table {
        u2 start_pc, end_pc;
        u2 handler_pc, catch_type;
}EXCEPTION_TABLE;

typedef struct line_number_table {
	u2 start_pc;
	u2 line_number;
}LINE_NUMBER_TABLE;

typedef struct line_number_table_attr {
	u2 attribute_name_index;
	u4 attribute_length;
        u2 line_number_table_length;
	LINE_NUMBER_TABLE *table_base;
}LINE_NUMBER_TABLE_ATTR;

union verification_type_info {
	u1 tag;
	struct {
		u1 tag;
		u2 cpool_index;
	}a;
	struct {
		u1 tag;
		u2 offset;
	}b;	
};

typedef struct stack_map_frame {
	union {
		struct same_frame {
			u1 frame_type;
		}a;
		struct same_locals_l_stack_item_frame {
			u1 frame_type;
			union verification_type_info *ver_info;
		}b;
		struct same_locals_l_stack_item_frame_extended {
			u1 frame_type;
			u2 offset_delta;
			union verification_type_info *ver_info;
		}c;
		struct chop_frame {
			u1 frame_type;
			u2 offset_delta;
		}d;
		struct same_frame_extended {
			u1 frame_type;
			u2 offset_delta;
		}e;
		struct append_frame {
			u1 frame_type;
			u2 offset_delta;
			union verification_type_info *ver_info;
		}f;
	};
	u1 frame_type;
	u1 stack_num;
        u1 locals_num;
	u1 offset_delta;
}STACK_MAP_FRAME;

typedef struct stack_map_attr {
	u2 attribute_name_index;
        u4 attribute_length;
        u2 number_of_entries;
	STACK_MAP_FRAME *stack_frame;
}STACK_MAP_ATTR;

typedef struct jvm_stack_frame {
        u1 *local_var_table;
        u1 *operand_stack;
        u4 *method;
        u1 *return_addr;
        u4 offset;
	u2 max_stack;
	u2 max_locals;
	struct jvm_stack_frame *prev_stack;
}JVM_STACK_FRAME;

typedef struct code_attr {
        u2 attribute_name_index;
        u4 attribute_length;
        u2 max_stack, max_locals;
        u2 exception_table_length;
        u2 attributes_count;
	u4 code_length;
        u1 *op_code;
	EXCEPTION_TABLE *exception_table;
	LINE_NUMBER_TABLE_ATTR *table_attr;
	STACK_MAP_ATTR *stack_map_attr;
	JVM_STACK_FRAME stack_frame;
	u4 *method;
}CLASS_CODE;

typedef struct exception_attr {
	u2 attribute_name_index;
	u4 attribute_length;
	u2 number_of_exceptions;
	u2 *exception_index_table;
}CLASS_EXCEPTION;

typedef struct synthetic_attr {
        u2 attribute_name_index;
        u4 attribute_length;
}CLASS_SYNTHETIC;

typedef struct deprecated_attr {
        u2 attribute_name_index;
        u4 attribute_length;
}CLASS_DEPRECATED;

typedef struct method_info {
        u2 access_flag;
        u2 name_index;
        u2 descriptor_index;
        u2 attributes_count;
        u1 *name_base;
        u1 *desc_base;
	CLASS_CODE *code_attr;
	CLASS_EXCEPTION *exception_attr;
	CLASS_SYNTHETIC *synthetic;
	CLASS_DEPRECATED *deprecated;
	struct jvm_class *class;
        struct list_head list;
}CLASS_METHOD;

typedef struct jvm_class {
        u4 class_magic;
        u2 minor_version;
        u2 major_version;
        u2 access_flag;
        u2 this_class;
        u2 super_class;
        u2 constant_pool_count;
	u2 interfaces_count;
        u2 fileds_count;
        u2 method_count;
	char class_file[1024];
	struct constant_info_st *constant_info;
	struct list_head interface_list_head;
        struct list_head filed_list_head;
        struct list_head method_list_head;
	u2 attributes_count;
	struct list_head list;
}CLASS;

typedef struct jvm_object {
	int age;
	int ref_count;
	CLASS *class;
}JVM_OBJECT;

typedef struct jvm_interp_env {
	struct constant_info_st *constant_info;
	struct jvm_interp_env *prev_env;
}JVM_INTERP_ENV;

typedef struct jvm_pc_st {
	u1 *pc;
}JVM_PC;

typedef struct jvm_arg {
	int print_class;
	int disass_class;
	char class_path[1024];
}JVM_ARG;

JVM_INTERP_ENV *curr_jvm_interp_env;
JVM_STACK_FRAME *curr_jvm_stack;
JVM_PC jvm_pc;
JVM_ARG *jvm_arg;

int jvm_stack_depth;
struct list_head jvm_class_list_head;

int mmap_class_file(const char *class_file);
int mmap_exit(void);
void init_class_parse(void);
void exit_class_parse(void);
void fix_class_info(struct list_head *list_head);
void print_class_info(struct list_head *list_head);
void print_line_number_table(LINE_NUMBER_TABLE_ATTR *table_attr);
void print_stack_map(STACK_MAP_ATTR *stack_map);
CLASS_METHOD *lookup_class_method(struct list_head *list_head, char *class_name,
	char *method_name);
int interp_bytecode(CLASS_METHOD *method);
int jvm_stack_init(void);
int jvm_pc_init(CLASS_METHOD *method);
int jvm_interp_env_init(void);
CLASS *jvm_load_class(const char *class_path, const char *class_name);
CLASS *jvm_parse_class_file(const char *class_file, const char *class_name);
int lookup_class_file(struct list_head *list_head, char *class_file);
CLASS_FILED *lookup_class_filed(struct list_head *list_head, char *class_name,
                char *method_name);
CLASS_FILED *lookup_class_filed(struct list_head *list_head, char *class_name,
                char *method_name);

int parse_synthetic_attribute(CLASS_METHOD *method, u2 index);

#endif
