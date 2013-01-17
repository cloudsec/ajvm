/*
 * Copyright (C) 2012, 2013 wzt		http://www.cloud-sec.org
 *
 * interp_engine.c
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
#include <assert.h>

#include "type.h"
#include "jvm.h"
#include "bytecode.h"
#include "list.h"
#include "log.h"
#include "vm_error.h"
	
#define push_operand_stack(type, value)							\
	do {										\
		print_local(curr_jvm_stack);						\
		*(type *)(curr_jvm_stack->operand_stack + 				\
			curr_jvm_stack->offset) = (type)value;				\	
        	curr_jvm_stack->offset += sizeof(type);					\
		print_local(curr_jvm_stack);						\
	} while(0);

#define pop_operand_stack(type, value)							\
	do {										\
		print_local(curr_jvm_stack);						\
	        curr_jvm_stack->offset -= sizeof(type);					\
        	value = *(type *)(curr_jvm_stack->operand_stack +			\
			curr_jvm_stack->offset);					\
        	*(type *)(curr_jvm_stack->operand_stack +				\
			curr_jvm_stack->offset) = '\0';					\
		print_local(curr_jvm_stack);						\
	} while(0);

#define copy_operand_stack(type, value)							\
	do {										\
		print_local(curr_jvm_stack);                                            \
                curr_jvm_stack->offset -= sizeof(type);                                 \
                value = *(type *)(curr_jvm_stack->operand_stack +                       \
                        curr_jvm_stack->offset);                                        \
		curr_jvm_stack->offset += sizeof(type);					\
                *(type *)(curr_jvm_stack->operand_stack +                               \
                        curr_jvm_stack->offset) = (type)value;                          \
                curr_jvm_stack->offset += sizeof(type);                                 \
                print_local(curr_jvm_stack);                                            \
        } while(0);

#define get_local_table(value, type, index)						\
	do {										\
		print_local(curr_jvm_stack);						\
		value = *(type *)(curr_jvm_stack->local_var_table + index * sizeof(type));\
		print_local(curr_jvm_stack);						\
	} while(0);
		
#define set_local_table(type, index, value)						\
	do {										\
		print_local(curr_jvm_stack);						\
		*(type *)(curr_jvm_stack->local_var_table + index * sizeof(type)) = value;\
		print_local(curr_jvm_stack);						\
	} while(0);

#define push_operand_stack_arg(jvm_stack, type, value)                                  \
        do {                                                                            \
                print_local(jvm_stack);                                            	\
                *(type *)(jvm_stack->operand_stack + jvm_stack->offset) = (type)value;  \
                jvm_stack->offset += sizeof(type);  	                                \
                print_local(jvm_stack);                  	                        \
        } while(0);

#define pop_operand_stack_arg(jvm_stack, type, value)                                   \
        do {                                                                            \
                print_local(jvm_stack);                                                 \
                jvm_stack->offset -= sizeof(type);                                 	\
                value = *(type *)(jvm_stack->operand_stack + jvm_stack->offset);        \
                *(type *)(jvm_stack->operand_stack + jvm_stack->offset) = '\0';         \
                print_local(jvm_stack);                                                 \
        } while(0);


#define set_local_table_arg(jvm_stack, type, index, value)                              \
        do {                                                                            \
                print_local(jvm_stack);                                                 \
                *(type *)(jvm_stack->local_var_table + index * sizeof(type)) = value;	\
                print_local(jvm_stack);                                                 \
        } while(0);

#ifdef VM_DEBUG
void print_local(JVM_STACK_FRAME *jvm_stack)
{
	int i;

	printf("#local: ");
	for (i = 0; i < jvm_stack->max_locals; i++)
		printf("0x%x ", *(int *)(jvm_stack->local_var_table + i * sizeof(int)));
	printf("\t#stack: ");
	for (i = 0; i < jvm_stack->max_stack; i++)
		printf("0x%x ", *(int *)(jvm_stack->operand_stack + i * sizeof(int)));
	printf("\n");
}
#else
void print_local(JVM_STACK_FRAME *jvm_stack)
{
}
#endif

#ifdef VM_DEBUG
void debug_vm_interp(char *fmt, ...)
{
	va_list arg;
	char buf[256];

	va_start(arg, fmt);
	vsprintf(buf, fmt, arg);
	va_end(arg);

	printf("%s", buf);
}
#else
void debug_vm_interp(char *fmt, ...)
{
}
#endif

void show_disassember_code(char *fmt, ...)
{
        va_list arg;
        char buf[256];

        va_start(arg, fmt);
        vsprintf(buf, fmt, arg);
        va_end(arg);

        printf("%s", buf);
}

int jvm_interp_nop(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
		show_disassember_code("%s\n", symbol);
		return 0;
	}
	debug_vm_interp("%s\n", symbol);
	jvm_pc.pc += len;

	return 0;
}

int jvm_interp_aconst_null(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
		printf("%s\n", symbol);
		return 0;
	}

	debug_vm_interp("%s\n", symbol);
	jvm_pc.pc += len;

	return 0;
}

#define JVM_INTERP_PUSH_CONST(type, value, fmt, ...)			\
	do {								\
        	if (jvm_arg->disass_class) {				\
			show_disassember_code(fmt, ##__VA_ARGS__);	\
                	return 0;					\
        	}							\
        	debug_vm_interp(fmt, ##__VA_ARGS__);			\
        	push_operand_stack(type, value)				\
        	jvm_pc.pc += len;					\
		return 0;						\
	} while (0);

int jvm_interp_iconst_m1(u2 len, char *symbol, void *base)
{
	JVM_INTERP_PUSH_CONST(int, -1, "%s\n", symbol)
}

int jvm_interp_iconst_0(u2 len, char *symbol, void *base)
{
	JVM_INTERP_PUSH_CONST(int, 0, "%s\n", symbol)
}

int jvm_interp_iconst_1(u2 len, char *symbol, void *base)
{
	JVM_INTERP_PUSH_CONST(int, 1, "%s\n", symbol)
}

int jvm_interp_iconst_2(u2 len, char *symbol, void *base)
{
	JVM_INTERP_PUSH_CONST(int, 2, "%s\n", symbol)
}

int jvm_interp_iconst_3(u2 len, char *symbol, void *base)
{
	JVM_INTERP_PUSH_CONST(int, 3, "%s\n", symbol)
}

int jvm_interp_iconst_4(u2 len, char *symbol, void *base)
{
	JVM_INTERP_PUSH_CONST(int, 4, "%s\n", symbol)
}

int jvm_interp_iconst_5(u2 len, char *symbol, void *base)
{
	JVM_INTERP_PUSH_CONST(int, 5, "%s\n", symbol)
}

int jvm_interp_lconst_0(u2 len, char *symbol, void *base)
{
	JVM_INTERP_PUSH_CONST(long, 0, "%s\n", symbol)
}

int jvm_interp_lconst_1(u2 len, char *symbol, void *base)
{
	JVM_INTERP_PUSH_CONST(long, 1, "%s\n", symbol)
}

int jvm_interp_fconst_0(u2 len, char *symbol, void *base)
{
	JVM_INTERP_PUSH_CONST(float, 0, "%s\n", symbol)
}

int jvm_interp_fconst_1(u2 len, char *symbol, void *base)
{
	JVM_INTERP_PUSH_CONST(float, 1, "%s\n", symbol)
}

int jvm_interp_fconst_2(u2 len, char *symbol, void *base)
{
	JVM_INTERP_PUSH_CONST(float, 2, "%s\n", symbol)
}

int jvm_interp_dconst_0(u2 len, char *symbol, void *base)
{
	JVM_INTERP_PUSH_CONST(double, 0, "%s\n", symbol)
}

int jvm_interp_dconst_1(u2 len, char *symbol, void *base)
{
	JVM_INTERP_PUSH_CONST(double, 1, "%s\n", symbol)
}

int jvm_interp_bipush(u2 len, char *symbol, void *base)
{
	u1 value;

	value = *(u1 *)(base + 1);
	JVM_INTERP_PUSH_CONST(int, value, "%s %d\n", symbol, value)
}

int jvm_interp_sipush(u2 len, char *symbol, void *base)
{
	u1 tmp1, tmp2;
	u4 value;

	value = (u4)(((*(u1 *)(base + 1)) << 8) | (*(u1 *)(base + 2)));
	JVM_INTERP_PUSH_CONST(int, value, "%s %d\n", symbol, value)
}

int jvm_interp_ldc(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
		printf("%s #%d\n", symbol, *(u1 *)(base + 1));
		return 0;
	}
}

int jvm_interp_ldc_w(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
		printf("%s %x %x\n", symbol, base + 1, base + 3);
		return 0;
	}
}

int jvm_interp_ldc2_w(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
		printf("%s %x %x\n", symbol, base + 1, base + 3);
		return 0;
	}
}

#define INTERP_LOAD_VAR(type, index, fmt, ...)                          \
        do {                                                            \
                u4 tmp;                                                 \
                                                                        \
                if (jvm_arg->disass_class) {                            \
                        show_disassember_code(fmt, ##__VA_ARGS__);      \
                        return 0;                                       \
                }                                                       \
                                                                        \
                debug_vm_interp(fmt, ##__VA_ARGS__);                    \
                get_local_table(tmp, type, index)                       \
                push_operand_stack(type, tmp)                           \
                jvm_pc.pc += len;                                       \
                return 0;                                               \
        } while (0);


int jvm_interp_iload(u2 len, char *symbol, void *base)
{
	u1 index;

	index = *(u1 *)(base + 1);
	INTERP_LOAD_VAR(int, index, "%s %d\n", symbol, index)
}

int jvm_interp_lload(u2 len, char *symbol, void *base)
{
	u1 index;

	index = *(u1 *)(base + 1);
	INTERP_LOAD_VAR(long, index, "%s %d\n", symbol, index)
}

int jvm_interp_fload(u2 len, char *symbol, void *base)
{
	u1 index;

	index = *(u1 *)(base + 1);
	INTERP_LOAD_VAR(float, index, "%s %d\n", symbol, index)
}

int jvm_interp_dload(u2 len, char *symbol, void *base)
{
	u1 index;

	index = *(u1 *)(base + 1);
	INTERP_LOAD_VAR(double, index, "%s %d\n", symbol, index)
}

int jvm_interp_aload(u2 len, char *symbol, void *base)
{
	u1 index;

	index = *(u1 *)(base + 1);
	INTERP_LOAD_VAR(int, index, "%s %d\n", symbol, index)
}

int jvm_interp_iload_0(u2 len, char *symbol, void *base)
{
	INTERP_LOAD_VAR(int, 0, "%s\n", symbol)
}

int jvm_interp_iload_1(u2 len, char *symbol, void *base)
{
	INTERP_LOAD_VAR(int, 1, "%s\n", symbol)
}

int jvm_interp_iload_2(u2 len, char *symbol, void *base)
{
	INTERP_LOAD_VAR(int, 2, "%s\n", symbol)
}

int jvm_interp_iload_3(u2 len, char *symbol, void *base)
{
	INTERP_LOAD_VAR(int, 3, "%s\n", symbol)
}

int jvm_interp_lload_0(u2 len, char *symbol, void *base)
{
	INTERP_LOAD_VAR(long, 0, "%s\n", symbol)
}

int jvm_interp_lload_1(u2 len, char *symbol, void *base)
{
	INTERP_LOAD_VAR(long, 1, "%s\n", symbol)
}

int jvm_interp_lload_2(u2 len, char *symbol, void *base)
{
	INTERP_LOAD_VAR(long, 2, "%s\n", symbol)
}

int jvm_interp_lload_3(u2 len, char *symbol, void *base)
{
	INTERP_LOAD_VAR(long, 3, "%s\n", symbol)
}

int jvm_interp_fload_0(u2 len, char *symbol, void *base)
{
	INTERP_LOAD_VAR(float, 0, "%s\n", symbol)
}

int jvm_interp_fload_1(u2 len, char *symbol, void *base)
{
	INTERP_LOAD_VAR(float, 1, "%s\n", symbol)
}

int jvm_interp_fload_2(u2 len, char *symbol, void *base)
{
	INTERP_LOAD_VAR(float, 2, "%s\n", symbol)
}

int jvm_interp_fload_3(u2 len, char *symbol, void *base)
{
	INTERP_LOAD_VAR(float, 3, "%s\n", symbol)
}

int jvm_interp_dload_0(u2 len, char *symbol, void *base)
{
	INTERP_LOAD_VAR(double, 0, "%s\n", symbol)
}

int jvm_interp_dload_1(u2 len, char *symbol, void *base)
{
	INTERP_LOAD_VAR(double, 1, "%s\n", symbol)
}

int jvm_interp_dload_2(u2 len, char *symbol, void *base)
{
	INTERP_LOAD_VAR(double, 2, "%s\n", symbol)
}

int jvm_interp_dload_3(u2 len, char *symbol, void *base)
{
	INTERP_LOAD_VAR(double, 3, "%s\n", symbol)
}

int jvm_interp_aload_0(u2 len, char *symbol, void *base)
{
	INTERP_LOAD_VAR(int, 0, "%s\n", symbol)
}

int jvm_interp_aload_1(u2 len, char *symbol, void *base)
{
	INTERP_LOAD_VAR(int, 1, "%s\n", symbol)
}

int jvm_interp_aload_2(u2 len, char *symbol, void *base)
{
	INTERP_LOAD_VAR(int, 2, "%s\n", symbol)
}

int jvm_interp_aload_3(u2 len, char *symbol, void *base)
{
	INTERP_LOAD_VAR(int, 3, "%s\n", symbol)
}

int jvm_interp_iaload(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_laload(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_faload(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_daload(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_aaload(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_baload(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_caload(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_saload(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

#define JVM_INTERP_STORE_CONST(type, index, fmt, ...)                   \
        do {                                                            \
                u4 tmp;                                                 \
                                                                        \
                if (jvm_arg->disass_class) {                            \
                        show_disassember_code(fmt, ##__VA_ARGS__);      \
                        return 0;                                       \
                }                                                       \
                                                                        \
                debug_vm_interp(fmt, ##__VA_ARGS__);                    \
                pop_operand_stack(type, tmp)                            \
                set_local_table(type, index, tmp)                       \
                jvm_pc.pc += len;                                       \
                                                                        \
                return 0;                                               \
        } while (0);

int jvm_interp_istore(u2 len, char *symbol, void *base)
{
	u1 index;

	index = *(u1 *)(base + 1);
	JVM_INTERP_STORE_CONST(int, index, "%s %d\n", symbol, index)
}

int jvm_interp_lstore(u2 len, char *symbol, void *base)
{
	u1 index;

	index = *(u1 *)(base + 1);
	JVM_INTERP_STORE_CONST(long, index, "%s %d\n", symbol, index)
}

int jvm_interp_fstore(u2 len, char *symbol, void *base)
{
	u1 index;

	index = *(u1 *)(base + 1);
	JVM_INTERP_STORE_CONST(float, index, "%s %d\n", symbol, index)
}

int jvm_interp_dstore(u2 len, char *symbol, void *base)
{
	u1 index;

	index = *(u1 *)(base + 1);
	JVM_INTERP_STORE_CONST(double, index, "%s %d\n", symbol, index)
}

int jvm_interp_astore(u2 len, char *symbol, void *base)
{
	u1 index;

	index = *(u1 *)(base + 1);
	JVM_INTERP_STORE_CONST(int, index, "%s %d\n", symbol, index)
}

int jvm_interp_istore_0(u2 len, char *symbol, void *base)
{
	JVM_INTERP_STORE_CONST(int, 0, "%s\n", symbol)
}

int jvm_interp_istore_1(u2 len, char *symbol, void *base)
{
	JVM_INTERP_STORE_CONST(int, 1, "%s\n", symbol)
}

int jvm_interp_istore_2(u2 len, char *symbol, void *base)
{
	JVM_INTERP_STORE_CONST(int, 2, "%s\n", symbol)
}

int jvm_interp_istore_3(u2 len, char *symbol, void *base)
{
	JVM_INTERP_STORE_CONST(int, 3, "%s\n", symbol)
}

int jvm_interp_lstore_0(u2 len, char *symbol, void *base)
{
	JVM_INTERP_STORE_CONST(long, 0, "%s\n", symbol)
}

int jvm_interp_lstore_1(u2 len, char *symbol, void *base)
{
	JVM_INTERP_STORE_CONST(long, 1, "%s\n", symbol)
}

int jvm_interp_lstore_2(u2 len, char *symbol, void *base)
{
	JVM_INTERP_STORE_CONST(long, 2, "%s\n", symbol)
}

int jvm_interp_lstore_3(u2 len, char *symbol, void *base)
{
	JVM_INTERP_STORE_CONST(long, 3, "%s\n", symbol)
}

int jvm_interp_fstore_0(u2 len, char *symbol, void *base)
{
	JVM_INTERP_STORE_CONST(float, 3, "%s\n", symbol)
}

int jvm_interp_fstore_1(u2 len, char *symbol, void *base)
{
	JVM_INTERP_STORE_CONST(float, 1, "%s\n", symbol)
}

int jvm_interp_fstore_2(u2 len, char *symbol, void *base)
{
	JVM_INTERP_STORE_CONST(float, 2, "%s\n", symbol)
}

int jvm_interp_fstore_3(u2 len, char *symbol, void *base)
{
	JVM_INTERP_STORE_CONST(float, 3, "%s\n", symbol)
}

int jvm_interp_dstore_0(u2 len, char *symbol, void *base)
{
	JVM_INTERP_STORE_CONST(double, 0, "%s\n", symbol)
}

int jvm_interp_dstore_1(u2 len, char *symbol, void *base)
{
	JVM_INTERP_STORE_CONST(double, 1, "%s\n", symbol)
}

int jvm_interp_dstore_2(u2 len, char *symbol, void *base)
{
	JVM_INTERP_STORE_CONST(double, 2, "%s\n", symbol)
}

int jvm_interp_dstore_3(u2 len, char *symbol, void *base)
{
	JVM_INTERP_STORE_CONST(double, 3, "%s\n", symbol)
}

int jvm_interp_astore_0(u2 len, char *symbol, void *base)
{
        u4 tmp;

	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}

        pop_operand_stack(int, tmp)
        set_local_table(int, 0, tmp)
        jvm_pc.pc += len;
}

int jvm_interp_astore_1(u2 len, char *symbol, void *base)
{
        u4 tmp;

	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}

        pop_operand_stack(int, tmp)
        set_local_table(int, 1, tmp)
        jvm_pc.pc += len;
}

int jvm_interp_astore_2(u2 len, char *symbol, void *base)
{
        u4 tmp;

	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}

        pop_operand_stack(int, tmp)
        set_local_table(int, 2, tmp)
        jvm_pc.pc += len;
}

int jvm_interp_astore_3(u2 len, char *symbol, void *base)
{
        u4 tmp;

	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}

        pop_operand_stack(int, tmp)
        set_local_table(int, 3, tmp)
        jvm_pc.pc += len;
}

int jvm_interp_iastore(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_lastore(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_fastore(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_dastore(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_aastore(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_bastore(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_castore(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_sastore(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_pop(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_pop2(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_dup(u2 len, char *symbol, void *base)
{
	int tmp;

	if (jvm_arg->disass_class) {
        	show_disassember_code("%s\n", symbol);
		return 0;
	}

	debug_vm_interp("%s\n", symbol);
	copy_operand_stack(int, tmp)
	jvm_pc.pc += len;
}

int jvm_interp_dup_x1(u2 len, char *symbol, void *base)
{
	int tmp;

        printf("%s\n", symbol);
}

int jvm_interp_dup_x2(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_dup2(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_dup2_x1(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_dup2_x2(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_swap(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

#define JVM_INTERP_ADD(type, fmt, ...)					\
	do {								\
        	type tmp1, tmp2;					\
        	if (jvm_arg->disass_class) {				\
			show_disassember_code(fmt, ##__VA_ARGS__);	\
                	return 0;					\
        	}							\
									\
        	debug_vm_interp(fmt, ##__VA_ARGS__);			\
		pop_operand_stack(type, tmp1)				\
		pop_operand_stack(type, tmp2)				\
        	push_operand_stack(type, (tmp1 + tmp2))			\
        	jvm_pc.pc += len;					\
		return 0;						\
	} while (0);

int jvm_interp_iadd(u2 len, char *symbol, void *base)
{
	JVM_INTERP_ADD(int, "%s\n", symbol)
}

int jvm_interp_ladd(u2 len, char *symbol, void *base)
{
	JVM_INTERP_ADD(long, "%s\n", symbol)
}

int jvm_interp_fadd(u2 len, char *symbol, void *base)
{
	JVM_INTERP_ADD(float, "%s\n", symbol)
}

int jvm_interp_dadd(u2 len, char *symbol, void *base)
{
	JVM_INTERP_ADD(double, "%s\n", symbol)
}

#define JVM_INTERP_SUB(type, fmt, ...)  	 	                \
        do {                                                            \
                type tmp1, tmp2;                                        \
                if (jvm_arg->disass_class) {                            \
                        show_disassember_code(fmt, ##__VA_ARGS__);      \
                        return 0;                                       \
                }                                                       \
                                                                        \
                debug_vm_interp(fmt, ##__VA_ARGS__);                    \
                pop_operand_stack(type, tmp1)                           \
                pop_operand_stack(type, tmp2)                           \
                push_operand_stack(type, (tmp2 - tmp1))                 \
                jvm_pc.pc += len;                                       \
                return 0;                                               \
        } while (0);

int jvm_interp_isub(u2 len, char *symbol, void *base)
{
	JVM_INTERP_SUB(int, "%s\n", symbol)
}

int jvm_interp_lsub(u2 len, char *symbol, void *base)
{
	JVM_INTERP_SUB(long, "%s\n", symbol)
}

int jvm_interp_fsub(u2 len, char *symbol, void *base)
{
	JVM_INTERP_SUB(float, "%s\n", symbol)
}

int jvm_interp_dsub(u2 len, char *symbol, void *base)
{
	JVM_INTERP_SUB(double, "%s\n", symbol)
}

#define JVM_INTERP_MUL(type, fmt, ...)                                  \
        do {                                                            \
                type tmp1, tmp2;                                        \
                if (jvm_arg->disass_class) {                            \
                        show_disassember_code(fmt, ##__VA_ARGS__);      \
                        return 0;                                       \
                }                                                       \
                                                                        \
                debug_vm_interp(fmt, ##__VA_ARGS__);                    \
                pop_operand_stack(type, tmp1)                           \
                pop_operand_stack(type, tmp2)                           \
                push_operand_stack(type, (tmp2 * tmp1))                 \
                jvm_pc.pc += len;                                       \
                return 0;                                               \
        } while (0);

int jvm_interp_imul(u2 len, char *symbol, void *base)
{
	JVM_INTERP_MUL(int, "%s\n", symbol)
}

int jvm_interp_lmul(u2 len, char *symbol, void *base)
{
	JVM_INTERP_MUL(long, "%s\n", symbol)
}

int jvm_interp_fmul(u2 len, char *symbol, void *base)
{
	JVM_INTERP_MUL(float, "%s\n", symbol)
}

int jvm_interp_dmul(u2 len, char *symbol, void *base)
{
	JVM_INTERP_MUL(double, "%s\n", symbol)
}

#define JVM_INTERP_DIV(type, fmt, ...)                                  \
        do {                                                            \
                type tmp1, tmp2; 	                                \
                if (jvm_arg->disass_class) {                            \
                        show_disassember_code(fmt, ##__VA_ARGS__);      \
                        return 0;                                       \
                }                                                       \
                                                                        \
                debug_vm_interp(fmt, ##__VA_ARGS__);                    \
                pop_operand_stack(type, tmp1)                           \
                pop_operand_stack(type, tmp2)                           \
                push_operand_stack(type, (tmp2 / tmp1))		        \
                jvm_pc.pc += len;                                       \
                return 0;                                               \
        } while (0);

int jvm_interp_idiv(u2 len, char *symbol, void *base)
{
	JVM_INTERP_DIV(int, "%s\n", symbol)
}

int jvm_interp_ldiv(u2 len, char *symbol, void *base)
{
	JVM_INTERP_DIV(long, "%s\n", symbol)
}

int jvm_interp_fdiv(u2 len, char *symbol, void *base)
{
	JVM_INTERP_DIV(float, "%s\n", symbol)
}

int jvm_interp_ddiv(u2 len, char *symbol, void *base)
{
	JVM_INTERP_DIV(double, "%s\n", symbol)
}

int jvm_interp_irem(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_lrem(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_frem(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_drem(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

#define JVM_INTERP_NEG(type, fmt, ...) 	                                \
        do {                                                            \
                type tmp;	                                        \
                if (jvm_arg->disass_class) {                            \
                        show_disassember_code(fmt, ##__VA_ARGS__);      \
                        return 0;                                       \
                }                                                       \
                                                                        \
                debug_vm_interp(fmt, ##__VA_ARGS__);                    \
                pop_operand_stack(type, tmp)                            \
                push_operand_stack(type, ((~tmp) + 1))	                \
                jvm_pc.pc += len;                                       \
                return 0;                                               \
        } while (0);


int jvm_interp_ineg(u2 len, char *symbol, void *base)
{
	JVM_INTERP_NEG(int, "%s\n", symbol)
}

int jvm_interp_lneg(u2 len, char *symbol, void *base)
{
	JVM_INTERP_NEG(long, "%s\n", symbol)
}

int jvm_interp_fneg(u2 len, char *symbol, void *base)
{
	//JVM_INTERP_NEG(float, "%s\n", symbol)
}

int jvm_interp_dneg(u2 len, char *symbol, void *base)
{
	//JVM_INTERP_NEG(double, "%s\n", symbol)
}

int jvm_interp_ishl(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_lshl(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_ishr(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_lshr(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_iushr(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_lushr(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

#define JVM_INTERP_AND(type, fmt, ...)                                  \
        do {                                                            \
                type tmp1, tmp2;                                        \
                if (jvm_arg->disass_class) {                            \
                        show_disassember_code(fmt, ##__VA_ARGS__);      \
                        return 0;                                       \
                }                                                       \
                                                                        \
                debug_vm_interp(fmt, ##__VA_ARGS__);                    \
                pop_operand_stack(type, tmp1)                           \
                pop_operand_stack(type, tmp2)                           \
                push_operand_stack(type, (tmp1 & tmp2))                 \
                jvm_pc.pc += len;                                       \
                return 0;                                               \
        } while (0);


int jvm_interp_iand(u2 len, char *symbol, void *base)
{
        JVM_INTERP_AND(int, "%s\n", symbol)
}

int jvm_interp_land(u2 len, char *symbol, void *base)
{
        JVM_INTERP_AND(long, "%s\n", symbol)
}

#define JVM_INTERP_OR(type, fmt, ...)                                   \
        do {                                                            \
                type tmp1, tmp2;                                        \
                if (jvm_arg->disass_class) {                            \
                        show_disassember_code(fmt, ##__VA_ARGS__);      \
                        return 0;                                       \
                }                                                       \
                                                                        \
                debug_vm_interp(fmt, ##__VA_ARGS__);                    \
                pop_operand_stack(type, tmp1)                           \
                pop_operand_stack(type, tmp2)                           \
                push_operand_stack(type, (tmp1 | tmp2))                 \
                jvm_pc.pc += len;                                       \
                return 0;                                               \
        } while (0);

int jvm_interp_ior(u2 len, char *symbol, void *base)
{
        JVM_INTERP_OR(int, "%s\n", symbol);
}

int jvm_interp_lor(u2 len, char *symbol, void *base)
{
        JVM_INTERP_OR(long, "%s\n", symbol);
}

#define JVM_INTERP_XOR(type, fmt, ...)                                   \
        do {                                                            \
                type tmp1, tmp2;                                        \
                if (jvm_arg->disass_class) {                            \
                        show_disassember_code(fmt, ##__VA_ARGS__);      \
                        return 0;                                       \
                }                                                       \
                                                                        \
                debug_vm_interp(fmt, ##__VA_ARGS__);                    \
                pop_operand_stack(type, tmp1)                           \
                pop_operand_stack(type, tmp2)                           \
                push_operand_stack(type, (tmp1 | tmp2))                 \
                jvm_pc.pc += len;                                       \
                return 0;                                               \
        } while (0);


int jvm_interp_ixor(u2 len, char *symbol, void *base)
{
        JVM_INTERP_XOR(int, "%s\n", symbol);
}

int jvm_interp_lxor(u2 len, char *symbol, void *base)
{
        JVM_INTERP_XOR(long, "%s\n", symbol);
}

int jvm_interp_iinc(u2 len, char *symbol, void *base)
{
	u1 index, value;
	u4 tmp;

	index = *(u1 *)(base + 1);
	value = *(u1 *)(base + 2);
	if (jvm_arg->disass_class) {
        	show_disassember_code("%s %d %d\n", symbol, index, value);
		return 0;
	}

       	debug_vm_interp("%s %d %d\n", symbol, index, value);
	get_local_table(tmp, int, index)
	tmp += value;
	set_local_table(int, index, tmp)
        jvm_pc.pc += len;
}

int jvm_interp_i2l(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_i2f(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}
int jvm_interp_i2d(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_l2i(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_l2f(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_l2d(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_f2i(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_f2l(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_f2d(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_d2i(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_d2l(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_d2f(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_i2b(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_i2c(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_i2s(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_lcmp(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_fcmpl(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_fcmpg(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_dcmpl(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_dcmpg(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_ifeq(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_ifne(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_iflt(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_ifge(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_ifgt(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_ifle(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

#define JVM_INTERP_IF_ICMP(type, symbol)                        \
        type tmp1, tmp2;                                        \
        u2 tmp;                                                 \
                                                                \
        tmp = (*(u1 *)(base + 1) << 8) | (*(u1 *)(base + 2));   \
        if (jvm_arg->disass_class) {                            \
                show_disassember_code("%s %d\n", symbol, tmp);  \
                return 0;                                       \
        }                                                       \
                                                                \
        debug_vm_interp("%s %d\n", symbol, tmp);                \
        pop_operand_stack(type, tmp2)                           \
        pop_operand_stack(type, tmp1)                

int jvm_interp_if_icmpeq(u2 len, char *symbol, void *base)
{
        JVM_INTERP_IF_ICMP(int, symbol)

        if (tmp1 == tmp2) {
                jvm_pc.pc += tmp;
        }
        else {
                jvm_pc.pc += len;
        }
}

int jvm_interp_if_icmpne(u2 len, char *symbol, void *base)
{
        JVM_INTERP_IF_ICMP(int, symbol)

        if (tmp1 != tmp2) {
                jvm_pc.pc += tmp;
        }
        else {
                jvm_pc.pc += len;
        }
}

int jvm_interp_if_icmplt(u2 len, char *symbol, void *base)
{
        JVM_INTERP_IF_ICMP(int, symbol)

        if (tmp1 < tmp2) {
                jvm_pc.pc += tmp;
        }
        else {
                jvm_pc.pc += len;
        }
}

int jvm_interp_if_icmpge(u2 len, char *symbol, void *base)
{
	JVM_INTERP_IF_ICMP(int, symbol)

	if (tmp1 >= tmp2) {
		jvm_pc.pc += tmp;
	}
	else {
		jvm_pc.pc += len;
	}
}

int jvm_interp_if_icmpgt(u2 len, char *symbol, void *base)
{
        JVM_INTERP_IF_ICMP(int, symbol)

        if (tmp1 > tmp2) {
                jvm_pc.pc += tmp;
        }
        else {
                jvm_pc.pc += len;
        }
}

int jvm_interp_if_icmple(u2 len, char *symbol, void *base)
{
        JVM_INTERP_IF_ICMP(int, symbol)

        if (tmp1 <= tmp2) {
                jvm_pc.pc += tmp;
        }
        else {
                jvm_pc.pc += len;
        }
}

int jvm_interp_if_acmpeq(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_if_acmpne(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_goto(u2 len, char *symbol, void *base)
{
        u4 tmp1, tmp2;
        u1 tmp;

        tmp = (*(char *)(base + 1) << 8) | (*(char *)(base + 2));
	if (jvm_arg->disass_class) {
        	show_disassember_code("%s 0x%x\n", symbol, tmp);
		return 0;
	}

	debug_vm_interp("%s 0x%x\n", symbol, tmp);
	jvm_pc.pc += tmp;

	return 0;
}

int jvm_interp_jsr(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_ret(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_tableswitch(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_lookupswitch(u2 len, char *symbol, void *base)
{
        printf("%s\n", symbol);
}

int jvm_interp_ireturn(u2 len, char *symbol, void *base)
{
	JVM_STACK_FRAME *prev_stack;
	u4 tmp;
	u1 *return_addr;

	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}

	return_addr = curr_jvm_stack->return_addr;
	printf("#return addr: 0x%x\n", return_addr);

	if (curr_jvm_stack->prev_stack)
		prev_stack = curr_jvm_stack->prev_stack;

	pop_operand_stack_arg(curr_jvm_stack, int, tmp);
	push_operand_stack_arg(prev_stack, int, tmp)

	if (curr_jvm_stack->prev_stack)
		curr_jvm_stack = curr_jvm_stack->prev_stack;
	print_local(curr_jvm_stack);

	if (curr_jvm_interp_env->prev_env)
		curr_jvm_interp_env = curr_jvm_interp_env->prev_env;

	jvm_stack_depth--;
	printf("!!%d\n", jvm_stack_depth);
        if (jvm_stack_depth == 0) {
                jvm_pc.pc += len;
	}
        else {
		printf("#return addr: 0x%x\n", return_addr);
                jvm_pc.pc = return_addr;
	}
}

int jvm_interp_lreturn(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
	jvm_pc.pc += len;
}

int jvm_interp_freturn(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
	        printf("%s\n", symbol);
		return 0;
	}

	jvm_pc.pc += len;
}

int jvm_interp_dreturn(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}

	jvm_pc.pc += len;
}

int jvm_interp_areturn(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}

	jvm_pc.pc += len;
}

int jvm_interp_return(u2 len, char *symbol, void *base)
{
	u1 *return_addr;
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}

	debug_vm_interp("%s\n", symbol);

	return_addr = curr_jvm_stack->return_addr;
	if (curr_jvm_stack->prev_stack)
        	curr_jvm_stack = curr_jvm_stack->prev_stack;
        print_local(curr_jvm_stack);
	if (curr_jvm_interp_env->prev_env)
		curr_jvm_interp_env = curr_jvm_interp_env->prev_env;

	jvm_stack_depth--;
	if (jvm_stack_depth == 0) {
		jvm_pc.pc += len;
	}
	else {
                jvm_pc.pc = return_addr;
	}
	return 0;
}

int jvm_interp_getstatic(u2 len, char *symbol, void *base)
{
        CLASS_FILED *filed;
        u2 class_index, name_index, desc_index;
        u2 index, idx;
        u1 *class_name;
        int value;

        index = (*(u1 *)(base + 1) << 8) | (*(u1 *)(base + 2));
        if (jvm_arg->disass_class) {
                printf("%s #%d\n", symbol, index);
                return 0;
        }

	debug_vm_interp("%s #%d\n", symbol, index);
        class_index = ((struct CONSTANT_Fieldref_info *)
                        curr_jvm_interp_env->constant_info[index].base)->class_index;

        class_index = ((struct CONSTANT_Class_info *)
                        curr_jvm_interp_env->constant_info[class_index].base)->name_index;
        class_name = curr_jvm_interp_env->constant_info[class_index].base;
        debug_vm_interp("#class name: %s\n", class_name);

        desc_index = ((struct CONSTANT_Fieldref_info *)
                        curr_jvm_interp_env->constant_info[index].base)->name_and_type_index;
        debug_vm_interp("#name_and_type_index: %d\n", desc_index);

        name_index = ((struct CONSTANT_NameAndType_info *)
                        curr_jvm_interp_env->constant_info[desc_index].base)->name_index;
        desc_index = ((struct CONSTANT_NameAndType_info *)
                        curr_jvm_interp_env->constant_info[desc_index].base)->descriptor_index;
        debug_vm_interp("#name_index: %d\tdescriptor_index: %d\n",
                name_index, desc_index);
        debug_vm_interp("#%s\t%s\n", curr_jvm_interp_env->constant_info[name_index].base,
                curr_jvm_interp_env->constant_info[desc_index].base);

        print_local(curr_jvm_stack);

        filed = lookup_class_filed(&jvm_class_list_head, class_name,
                        curr_jvm_interp_env->constant_info[name_index].base);
        if (!filed) {
                jvm_error(VM_ERROR_INTERP, "JVM interpret error.");
        }
        debug_vm_interp("#found filed: %s\n", curr_jvm_interp_env->constant_info[name_index].base);

	value = filed->value1;
        push_operand_stack(int, value)
        print_local(curr_jvm_stack);

        jvm_pc.pc += len;

        return 0;
}

int jvm_interp_putstatic(u2 len, char *symbol, void *base)
{
	CLASS_FILED *filed;
        u2 class_index, name_index, desc_index;
        u2 index, idx;
        u1 *class_name;
	int value;

        index = (*(u1 *)(base + 1) << 8) | (*(u1 *)(base + 2));
	if (jvm_arg->disass_class) {
        	printf("%s #%d\n", symbol, index);
		return 0;
	}

	debug_vm_interp("%s #%d\n", symbol, value);
        class_index = ((struct CONSTANT_Fieldref_info *)
                        curr_jvm_interp_env->constant_info[index].base)->class_index;
        class_index = ((struct CONSTANT_Class_info *)
                        curr_jvm_interp_env->constant_info[class_index].base)->name_index;
        class_name = curr_jvm_interp_env->constant_info[class_index].base;
        debug_vm_interp("#class name: %s\n", class_name);

        desc_index = ((struct CONSTANT_Fieldref_info *)
                        curr_jvm_interp_env->constant_info[index].base)->name_and_type_index;
        debug_vm_interp("#name_and_type_index: %d\n", desc_index);

        name_index = ((struct CONSTANT_NameAndType_info *)
                        curr_jvm_interp_env->constant_info[desc_index].base)->name_index;
        desc_index = ((struct CONSTANT_NameAndType_info *)
                        curr_jvm_interp_env->constant_info[desc_index].base)->descriptor_index;
        debug_vm_interp("#name_index: %d\tdescriptor_index: %d\n",
                name_index, desc_index);
        debug_vm_interp("#%s\t%s\n", curr_jvm_interp_env->constant_info[name_index].base,
                curr_jvm_interp_env->constant_info[desc_index].base);

        print_local(curr_jvm_stack);

        filed = lookup_class_filed(&jvm_class_list_head, class_name,
                	curr_jvm_interp_env->constant_info[name_index].base);
        if (!filed) {
                jvm_error(VM_ERROR_INTERP, "JVM interpret error.");
        }
        debug_vm_interp("#found filed: %s\n", curr_jvm_interp_env->constant_info[name_index].base);

	pop_operand_stack(int, value)
        print_local(curr_jvm_stack);

	filed->value1 = value;
	jvm_pc.pc += len;

	return 0;
}

int jvm_interp_getfiled(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_putfiled(u2 len, char *symbol, void *base)
{
	CLASS_FILED *filed;
	JVM_OBJECT *object = NULL;
        u2 class_index, name_index, desc_index;
        u2 index, idx;
        u1 *class_name;
 	int value;

        index = ((*(u1 *)(base + 1)) << 8) | (*(u1 *)(base + 2));
	if (jvm_arg->disass_class) {
        	printf("%s #%x\n", symbol, index);
		return 0;
	}

        class_index = ((struct CONSTANT_Fieldref_info *)
                        curr_jvm_interp_env->constant_info[index].base)->class_index;
        class_index = ((struct CONSTANT_Class_info *)
                        curr_jvm_interp_env->constant_info[class_index].base)->name_index;
        class_name = curr_jvm_interp_env->constant_info[class_index].base;
        debug_vm_interp("#class name: %s\n", class_name);

        desc_index = ((struct CONSTANT_Methodref_info *)
                        curr_jvm_interp_env->constant_info[index].base)->name_and_type_index;
        debug_vm_interp("#name_and_type_index: %d\n", desc_index);

        name_index = ((struct CONSTANT_NameAndType_info *)
                        curr_jvm_interp_env->constant_info[desc_index].base)->name_index;
        desc_index = ((struct CONSTANT_NameAndType_info *)
                        curr_jvm_interp_env->constant_info[desc_index].base)->descriptor_index;
        debug_vm_interp("#name_index: %d\tdescriptor_index: %d\n",
                name_index, desc_index);
        debug_vm_interp("#%s\t%s\n", curr_jvm_interp_env->constant_info[name_index].base,
                curr_jvm_interp_env->constant_info[desc_index].base);

	print_local(curr_jvm_stack);

	filed = lookup_class_filed(&jvm_class_list_head, class_name,
		curr_jvm_interp_env->constant_info[name_index].base);
	if (!filed) {
		__error("interpret error.");
		exit(-1);
	}
	debug_vm_interp("#found filed: %s\n", curr_jvm_interp_env->constant_info[name_index].base);
	pop_operand_stack(int, value)
	pop_operand_stack(int, object)
	debug_vm_interp("#object: 0x%x\tvalue: %d\n", object, value);

	jvm_pc.pc += len;
	return 0;
}

void push_method_arg(JVM_STACK_FRAME *prev, JVM_STACK_FRAME *curr, 
		CLASS_METHOD *method)
{
	int idx, len = 0;
	char *s;
	u2 local_idx = 1;  
	u4 tmp;

	printf("#push method arg:\n");
	s = method->desc_base;
	while (*s != ')') {
		if (*s == 'I') {
			len++;
			s++;
			continue;
		}
		s++;
	}

	for (idx = 0; idx < len; idx++) {
		printf("................\n");
		pop_operand_stack_arg(prev, int, tmp)
		if (method->access_flag & METHOD_ACC_STATIC) {
			printf("#static flag.\n");
			set_local_table_arg(curr, int, (len - idx - 1), tmp)
		}
		else {
			printf("#public flag.\n");
			set_local_table_arg(curr, int, (len - idx), tmp)
		}
	}
}

int push_method_arg1(JVM_STACK_FRAME *prev, JVM_STACK_FRAME *curr,
                CLASS_METHOD *method)
{
/*
	char *s;
	int idx, arg_len;

        debug_vm_interp("#push method arg:\n");
        s = method->desc_base + 1;
	arg_len = method->code_attr->stack_frame.max_locals;
	for (idx = 0; idx < arg_len ; idx++) {
		switch (*s) {
		case ARG_BYTE: 
        		pop_operand_stack_arg(prev, u1, tmp)
        		set_local_table_arg(curr, u1, len - idx, tmp)
			s++;
			break;
		case ARG_CHAR:
			arg_type[var_index++] = ARG_CHAR;
			arg_len++;s++;
			break;
		case ARG_DOUBLE:
			arg_type[var_index++] = ARG_DOUBLE;
			arg_len++;s++;
			break;
		case ARG_FLOAT:
			arg_type[var_index++] = ARG_FLOAT;
			arg_len++;s++;
			break;
		case ARG_INT:
			arg_type[var_index++] = ARG_INT;
			arg_len++;s++;
			break;
		case ARG_LONG:
			arg_type[var_index++] = ARG_LONG;
			arg_len++;s++;
			break;
		case ARG_REFERENCE:
			arg_type[var_index++] = ARG_REFERENCE;
			arg_len++;s++;
			break;
		case ARG_SHORT:
			arg_type[var_index++] = ARG_SHORT;
			arg_len++;s++;
			break;
		case ARG_BOOLEAN:
			arg_type[var_index++] = ARG_BOOLEAN;
			arg_len++;s++;
			break;
		case ARG_ARRAY:
			arg_type[var_index++] = ARG_ARRAY;
			arg_len++;s++;
			break;
		default:
			jvm_error(VM_ERROR_INTERP, "JVM interp method arg failed.");
			return -1;
		}
	}

	for (; var_index >= 0; var_index--) {
	}

        pop_operand_stack_arg(prev, int, tmp)
        set_local_table_arg(curr, int, 0, tmp)
        for (idx = 0; idx < len; idx++) {
                printf("................\n");
                pop_operand_stack_arg(prev, int, tmp)
                set_local_table_arg(curr, int, (len - idx), tmp)
        }
*/
        int idx, len = 0;
        char *s;
        u2 local_idx = 1;
        u4 tmp;

        printf("#push method arg:\n");
        s = method->desc_base;
        while (*s != ')') {
                if (*s == 'I') {
                        len++;
                        s++;
                        continue;
                }
                s++;
        }

        pop_operand_stack_arg(prev, int, tmp)
        set_local_table_arg(curr, int, 0, tmp)
        for (idx = 0; idx < len; idx++) {
                printf("................\n");
                pop_operand_stack_arg(prev, int, tmp)
                set_local_table_arg(curr, int, (len - idx), tmp)
        }
}

CLASS_METHOD *handle_interp_invoke(u2 index)
{
        CLASS_METHOD *method;
        u2 class_index, name_index, desc_index, idx;
        u1 *class_name;

        class_index = ((struct CONSTANT_Methodref_info *)
                        curr_jvm_interp_env->constant_info[index].base)->class_index;
        class_index = ((struct CONSTANT_Class_info *)
                        curr_jvm_interp_env->constant_info[class_index].base)->name_index;
        class_name = curr_jvm_interp_env->constant_info[class_index].base;
        debug_vm_interp("#class name: %s\n", class_name);

        desc_index = ((struct CONSTANT_Methodref_info *)
                        curr_jvm_interp_env->constant_info[index].base)->name_and_type_index;
        debug_vm_interp("#name_and_type_index: %d\n", desc_index);

        name_index = ((struct CONSTANT_NameAndType_info *)
                        curr_jvm_interp_env->constant_info[desc_index].base)->name_index;
        desc_index = ((struct CONSTANT_NameAndType_info *)
                        curr_jvm_interp_env->constant_info[desc_index].base)->descriptor_index;
        debug_vm_interp("#name_index: %d\tdescriptor_index: %d\n", name_index, desc_index);
        debug_vm_interp("#%s\t%s\n", curr_jvm_interp_env->constant_info[name_index].base,
                curr_jvm_interp_env->constant_info[desc_index].base);

        method = lookup_class_method(&jvm_class_list_head, class_name,
                        curr_jvm_interp_env->constant_info[name_index].base);
        if (!method) {
                CLASS *new_class;
                char tmp[1024];

                snprintf(tmp, 1024, "%s/%s.class", jvm_arg->class_path, class_name);
                debug_vm_interp("# loading class: %s\n", tmp);
                new_class = jvm_parse_class_file(tmp, class_name);
                if (!new_class) {
                        jvm_error(VM_ERROR_INTERP, "JVM interp error.");
                        return NULL; 
                }
                method = lookup_class_method(&jvm_class_list_head, class_name,
                                curr_jvm_interp_env->constant_info[name_index].base);
                if (!method) {
                        jvm_error(VM_ERROR_INTERP, "JVM interp error.");
                        return NULL;
                }
        }
        debug_vm_interp("#found method: %s\n", curr_jvm_interp_env->constant_info[name_index].base);
        debug_vm_interp("print method code:\n");
        debug_vm_interp("#");
        for (idx = 0; idx < method->code_attr->code_length; idx++)
                debug_vm_interp("0x%x ", *(u1 *)(method->code_attr->op_code + idx));
        debug_vm_interp("\n");

	return method;
}

JVM_STACK_FRAME *handle_interp_stack(CLASS_METHOD *method, u2 len)
{
        JVM_STACK_FRAME *prev_stack_frame;

        prev_stack_frame = (JVM_STACK_FRAME *)malloc(sizeof(JVM_STACK_FRAME));
        if (!prev_stack_frame) {
		jvm_error(VM_ERROR_MEMORY, "JVM malloc failed.");
                return NULL;
        }
        memcpy(prev_stack_frame, curr_jvm_stack, sizeof(JVM_STACK_FRAME));

        curr_jvm_stack = &method->code_attr->stack_frame;
        curr_jvm_stack->prev_stack = prev_stack_frame;
        curr_jvm_stack->return_addr = jvm_pc.pc + len;
        debug_vm_interp("retrun addr: 0x%x\n", curr_jvm_stack->return_addr);

        print_local(prev_stack_frame);
        print_local(curr_jvm_stack);
        debug_vm_interp("#prev: %d %d\tcurr: %d %d\n",
                prev_stack_frame->max_locals, prev_stack_frame->max_stack,
                curr_jvm_stack->max_locals, curr_jvm_stack->max_stack);

	return prev_stack_frame;
}

int handle_interp_env(CLASS_METHOD *method)
{
        JVM_INTERP_ENV *prev_env;

        prev_env = (JVM_INTERP_ENV *)malloc(sizeof(JVM_INTERP_ENV));
        if (!prev_env) {
                jvm_error(VM_ERROR_MEMORY, "JVM malloc failed.");
                return -1;
        }
        memset(prev_env, '\0', sizeof(JVM_INTERP_ENV));
        memcpy(prev_env, curr_jvm_interp_env, sizeof(JVM_INTERP_ENV));

        curr_jvm_interp_env->constant_info = method->class->constant_info;
        curr_jvm_interp_env->prev_env = prev_env;

	return 0;
}

int jvm_interp_invoke(u2 index, u2 len)
{
        CLASS_METHOD *method;
        JVM_STACK_FRAME *prev_stack_frame;

        method = handle_interp_invoke(index);
        if (!method) {
                __error("interpret error.");
                return -1;
        }

        prev_stack_frame = handle_interp_stack(method, len);
        if (!prev_stack_frame) {
                __error("interpret error.");
                return -1;
        }

        if (handle_interp_env(method) == -1) {
                __error("interpret error.");
                return -1;
        }

        jvm_stack_depth++;
        jvm_pc.pc = method->code_attr->op_code;
}

int jvm_interp_invokespecial(u2 len, char *symbol, void *base)
{
        CLASS_METHOD *method;
        JVM_STACK_FRAME *prev_stack_frame;
        u2 index;

        index = ((*(u1 *)(base + 1)) << 8) | (*(u1 *)(base + 2));
	if (jvm_arg->disass_class) {
        	show_disassember_code("%s #%x\n", symbol, index);
		return 0;
	}

	debug_vm_interp("%s #%x\n", symbol, index);
	method = handle_interp_invoke(index);
	if (!method) {
		jvm_error(VM_ERROR_INTERP, "JVM interp error.");
		return -1;
	}

	prev_stack_frame = handle_interp_stack(method, len);
	if (!prev_stack_frame) {
		jvm_error(VM_ERROR_INTERP, "JVM interp error.");
		return -1;
	}

	if (handle_interp_env(method) == -1) {
		jvm_error(VM_ERROR_INTERP, "JVM interp error.");
		return -1;
	}

        jvm_stack_depth++;
        jvm_pc.pc = method->code_attr->op_code;

        push_method_arg1(prev_stack_frame, curr_jvm_stack, method);
}

int jvm_interp_invokestatic(u2 len, char *symbol, void *base)
{
        CLASS_METHOD *method;
        JVM_STACK_FRAME *prev_stack_frame;
        u2 index;

        index = ((*(u1 *)(base + 1)) << 8) | (*(u1 *)(base + 2));
	if (jvm_arg->disass_class) {
        	printf("%s #%x\n", symbol, index);
		return 0;
	}

        method = handle_interp_invoke(index);
        if (!method) {
                __error("interpret error.");
                exit(-1);
        }

        prev_stack_frame = handle_interp_stack(method, len);
        if (!prev_stack_frame) {
                __error("interpret error.");
                exit(-1);
        }

        if (handle_interp_env(method) == -1) {
                __error("interpret error.");
                exit(-1);
        }

        jvm_stack_depth++;
        jvm_pc.pc = method->code_attr->op_code;

        push_method_arg(prev_stack_frame, curr_jvm_stack, method);
}

int jvm_interp_invokevirtual(u2 len, char *symbol, void *base)
{
        CLASS_METHOD *method;
        JVM_STACK_FRAME *prev_stack_frame;
        u2 index;

        index = ((*(u1 *)(base + 1)) << 8) | (*(u1 *)(base + 2));
	if (jvm_arg->disass_class) {
        	printf("%s #%x\n", symbol, index);
		return 0;
	}

        method = handle_interp_invoke(index);
        if (!method) {
                __error("interpret error.");
                exit(-1);
        }

        prev_stack_frame = handle_interp_stack(method, len);
        if (!prev_stack_frame) {
                __error("interpret error.");
                exit(-1);
        }

        if (handle_interp_env(method) == -1) {
                __error("interpret error.");
                exit(-1);
        }

        jvm_stack_depth++;
        jvm_pc.pc = method->code_attr->op_code;

        push_method_arg(prev_stack_frame, curr_jvm_stack, method);
}

int jvm_interp_invokeinterface(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_invokedynamic(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_new(u2 len, char *symbol, void *base)
{
	JVM_OBJECT *new_object;
	CLASS *new_class;
	char *class_name;
	u2 name_index, tmp;

        tmp = (*(u1 *)(base + 1) << 8) | (*(u1 *)(base + 2));
	if (jvm_arg->disass_class) {
        	show_disassember_code("%s #%d\n", symbol, tmp);
		return 0;
	}

	debug_vm_interp("%s #%d\n", symbol, tmp);
        name_index = ((struct CONSTANT_Class_info *)
                        curr_jvm_interp_env->constant_info[tmp].base)->name_index;
        debug_vm_interp("#name_index: %d\n", name_index);

	class_name = curr_jvm_interp_env->constant_info[name_index].base;
	debug_vm_interp("#%s\n", class_name);

	if (!lookup_class_file(&jvm_class_list_head, class_name)) {
		debug_vm_interp("class: %s was already loaded.\n", class_name);
		goto object;
	}

	new_class = jvm_load_class(jvm_arg->class_path, class_name);
	if (!new_class) {
		jvm_error(VM_ERROR_INTERP, "JVM interp failed");
		return -1;
	}
	debug_vm_interp("#loading class_file: %s ok.\n", class_name);

object:
	new_object = (JVM_OBJECT *)malloc(sizeof(JVM_OBJECT));
	if (!new_object) {
		free(new_class);
		jvm_error(VM_ERROR_MEMORY, "JVM malloc failed.");
		return -1;
	}

	new_object->age = 0;
	new_object->ref_count = 0;
	new_object->class = new_class;

	push_operand_stack(int, new_object)
	jvm_pc.pc += len;
	return 0;
}

int jvm_interp_newarray(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_anewarray(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_arraylength(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_athrow(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_checkcast(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_instanceof(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_monitorenter(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_monitorexit(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_wide(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_multianewarray(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_ifnull(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_ifnonnull(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_goto_w(u2 len, char *symbol, void *base)
{
        u2 tmp;

        tmp = (*(u1 *)(base + 1) << 8) | (*(u1 *)(base + 2));
	if (jvm_arg->disass_class) {
        	printf("%s %d\n", symbol, tmp);
		return 0;
	}
}

int jvm_interp_jsr_w(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_getfield(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int jvm_interp_putfield(u2 len, char *symbol, void *base)
{
	if (jvm_arg->disass_class) {
        	printf("%s\n", symbol);
		return 0;
	}
}

int __disass_bytecode(u1 *base, u2 len)
{
	u1 idx = 0;
	u1 index;

	while (idx < len) {
		index = *(u1 *)(base + idx);
		jvm_byte_code[index].func(jvm_byte_code[index].opcode_len,
			jvm_byte_code[index].symbol, base + idx);
		idx += (u1)jvm_byte_code[index].opcode_len;
	}
}

int disass_bytecode(struct list_head *list_head)
{
        struct list_head *s;
	CLASS_METHOD *p;

	printf("Diassember bytecode:\n\n");
        list_for_each(s, list_head) {
                p = list_entry(s, CLASS_METHOD, list);
                if (p) {
			printf("%s\t%s\n", p->name_base, p->desc_base);
			printf("stack: %d\tlocal: %d\n\n", p->code_attr->max_stack, 
				p->code_attr->max_locals);
			__disass_bytecode(p->code_attr->op_code, p->code_attr->code_length);
			if (p->code_attr->table_attr)
				print_line_number_table(p->code_attr->table_attr);
			if (p->code_attr->stack_map_attr)
				print_stack_map(p->code_attr->stack_map_attr);
			printf("\n-----------------------------\n");
                }
        }
}

int compute_stack_size(struct list_head *list_head)
{
        struct list_head *s;
	CLASS_METHOD *p;
	int size = 0;

        list_for_each(s, list_head) {
                p = list_entry(s, CLASS_METHOD, list);
		if (p && p->code_attr) {
			size += (int)p->code_attr->max_stack * sizeof(int);
			size += (int)p->code_attr->max_locals * sizeof(int);
		}
	}

	return size;	
}

int jvm_stack_init(void)
{
	curr_jvm_stack = (JVM_STACK_FRAME *)malloc(sizeof(JVM_STACK_FRAME));
	if (!curr_jvm_stack) {
		__error("malloc failed.");
		return -1;
	}
	memset(curr_jvm_stack, '\0', sizeof(JVM_STACK_FRAME));

	jvm_stack_depth = 0;

	return 0;
}

int jvm_pc_init(CLASS_METHOD *method)
{
	jvm_pc.pc = (u1 *)method->code_attr->op_code;

	debug_vm_interp("jvm pc init at: 0x%x\n\n", jvm_pc.pc);
}

int jvm_interp_env_init(void)
{
	curr_jvm_interp_env = (JVM_INTERP_ENV *)malloc(sizeof(JVM_INTERP_ENV));
	if (!curr_jvm_interp_env) {
		__error("malloc failed.");
		return -1;
	}

	return 0;
}

void jvm_interp_env_exit(void)
{
	free(curr_jvm_interp_env);
}

void show_method_code(CLASS_METHOD *method)
{
	u4 idx;

	debug_vm_interp("code: ");
	for (idx = 0; idx < method->code_attr->code_length; idx++)
		debug_vm_interp("0x%x ", *(u1 *)(method->code_attr->op_code + idx));
	debug_vm_interp("\n");
}

int interp_bytecode(CLASS_METHOD *method)
{
	u1 index, idx;
	u4 pc_count = 1;

	debug_vm_interp("%s\t%s\n", method->name_base, method->desc_base);
	debug_vm_interp("stack: %d\tlocal : %d\n", method->code_attr->max_stack, 
			method->code_attr->max_locals);

	show_method_code(method);
	jvm_stack_depth++;
	curr_jvm_stack = &method->code_attr->stack_frame;
	debug_vm_interp("#local at: 0x%x\t#stack at: 0x%x\n\n",
			curr_jvm_stack->local_var_table,
			curr_jvm_stack->operand_stack);

	curr_jvm_interp_env->constant_info = method->class->constant_info;
	curr_jvm_interp_env->prev_env = NULL;
	for (;;) {
		if (jvm_stack_depth == 0) {
			debug_vm_interp("interpret bytecode done.\n");
			break;
		}

		index = *(u1 *)jvm_pc.pc;
		debug_vm_interp("[%d] %s\tpc: 0x%x -> 0x%x\n", 
			pc_count++, jvm_byte_code[index].symbol, jvm_pc.pc, index);
		jvm_byte_code[index].func(jvm_byte_code[index].opcode_len,
			jvm_byte_code[index].symbol, jvm_pc.pc);
	}
}
