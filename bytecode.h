/*
 * bytecode.h (c) 2012, 2013 wzt	http://www.cloud-sec.org
 *
 */

#ifndef BYTECODE_H
#define BYTECODE_H

#define OPCODE_SYMBOL_LEN			16
#define OPCODE_LEN				0xca

#include "type.h"

typedef int (*interp_func)(u2 opcode_len, char *symbol, void *base);

typedef struct bytecode_st {
	u2 opcode;
	u2 opcode_len;
	char symbol[OPCODE_SYMBOL_LEN];
	interp_func func;
}BYTECODE;

int jvm_interp_nop(u2 len, char *symbol, void *base);
int jvm_interp_aconst_null(u2 len, char *symbol, void *base);
int jvm_interp_iconst_m1(u2 len, char *symbol, void *base);
int jvm_interp_iconst_0(u2 len, char *symbol, void *base);
int jvm_interp_iconst_1(u2 len, char *symbol, void *base);
int jvm_interp_iconst_2(u2 len, char *symbol, void *base);
int jvm_interp_iconst_3(u2 len, char *symbol, void *base);
int jvm_interp_iconst_4(u2 len, char *symbol, void *base);
int jvm_interp_iconst_5(u2 len, char *symbol, void *base);
int jvm_interp_lconst_0(u2 len, char *symbol, void *base);
int jvm_interp_lconst_1(u2 len, char *symbol, void *base);
int jvm_interp_fconst_0(u2 len, char *symbol, void *base);
int jvm_interp_fconst_1(u2 len, char *symbol, void *base);
int jvm_interp_fconst_2(u2 len, char *symbol, void *base);
int jvm_interp_dconst_0(u2 len, char *symbol, void *base);
int jvm_interp_dconst_1(u2 len, char *symbol, void *base);
int jvm_interp_bipush(u2 len, char *symbol, void *base);
int jvm_interp_sipush(u2 len, char *symbol, void *base);
int jvm_interp_ldc(u2 len, char *symbol, void *base);
int jvm_interp_ldc_w(u2 len, char *symbol, void *base);
int jvm_interp_ldc2_w(u2 len, char *symbol, void *base);
int jvm_interp_iload(u2 len, char *symbol, void *base);
int jvm_interp_lload(u2 len, char *symbol, void *base);
int jvm_interp_fload(u2 len, char *symbol, void *base);
int jvm_interp_dload(u2 len, char *symbol, void *base);
int jvm_interp_aload(u2 len, char *symbol, void *base);
int jvm_interp_iload_0(u2 len, char *symbol, void *base);
int jvm_interp_iload_1(u2 len, char *symbol, void *base);
int jvm_interp_iload_2(u2 len, char *symbol, void *base);
int jvm_interp_iload_3(u2 len, char *symbol, void *base);
int jvm_interp_lload_0(u2 len, char *symbol, void *base);
int jvm_interp_lload_1(u2 len, char *symbol, void *base);
int jvm_interp_lload_2(u2 len, char *symbol, void *base);
int jvm_interp_lload_3(u2 len, char *symbol, void *base);
int jvm_interp_fload_0(u2 len, char *symbol, void *base);
int jvm_interp_fload_1(u2 len, char *symbol, void *base);
int jvm_interp_fload_2(u2 len, char *symbol, void *base);
int jvm_interp_fload_3(u2 len, char *symbol, void *base);
int jvm_interp_dload_0(u2 len, char *symbol, void *base);
int jvm_interp_dload_1(u2 len, char *symbol, void *base);
int jvm_interp_dload_2(u2 len, char *symbol, void *base);
int jvm_interp_dload_3(u2 len, char *symbol, void *base);
int jvm_interp_aload_0(u2 len, char *symbol, void *base);
int jvm_interp_aload_1(u2 len, char *symbol, void *base);
int jvm_interp_aload_2(u2 len, char *symbol, void *base);
int jvm_interp_aload_3(u2 len, char *symbol, void *base);
int jvm_interp_iaload(u2 len, char *symbol, void *base);
int jvm_interp_laload(u2 len, char *symbol, void *base);
int jvm_interp_faload(u2 len, char *symbol, void *base);
int jvm_interp_daload(u2 len, char *symbol, void *base);
int jvm_interp_aaload(u2 len, char *symbol, void *base);
int jvm_interp_baload(u2 len, char *symbol, void *base);
int jvm_interp_caload(u2 len, char *symbol, void *base);
int jvm_interp_saload(u2 len, char *symbol, void *base);
int jvm_interp_istore(u2 len, char *symbol, void *base);
int jvm_interp_lstore(u2 len, char *symbol, void *base);
int jvm_interp_fstore(u2 len, char *symbol, void *base);
int jvm_interp_dstore(u2 len, char *symbol, void *base);
int jvm_interp_astore(u2 len, char *symbol, void *base);
int jvm_interp_istore_0(u2 len, char *symbol, void *base);
int jvm_interp_istore_1(u2 len, char *symbol, void *base);
int jvm_interp_istore_2(u2 len, char *symbol, void *base);
int jvm_interp_istore_3(u2 len, char *symbol, void *base);
int jvm_interp_lstore_0(u2 len, char *symbol, void *base);
int jvm_interp_lstore_1(u2 len, char *symbol, void *base);
int jvm_interp_lstore_2(u2 len, char *symbol, void *base);
int jvm_interp_lstore_3(u2 len, char *symbol, void *base);
int jvm_interp_fstore_0(u2 len, char *symbol, void *base);
int jvm_interp_fstore_1(u2 len, char *symbol, void *base);
int jvm_interp_fstore_2(u2 len, char *symbol, void *base);
int jvm_interp_fstore_3(u2 len, char *symbol, void *base);
int jvm_interp_dstore_0(u2 len, char *symbol, void *base);
int jvm_interp_dstore_1(u2 len, char *symbol, void *base);
int jvm_interp_dstore_2(u2 len, char *symbol, void *base);
int jvm_interp_dstore_3(u2 len, char *symbol, void *base);
int jvm_interp_astore_0(u2 len, char *symbol, void *base);
int jvm_interp_astore_1(u2 len, char *symbol, void *base);
int jvm_interp_astore_2(u2 len, char *symbol, void *base);
int jvm_interp_astore_3(u2 len, char *symbol, void *base);
int jvm_interp_iastore(u2 len, char *symbol, void *base);
int jvm_interp_lastore(u2 len, char *symbol, void *base);
int jvm_interp_fastore(u2 len, char *symbol, void *base);
int jvm_interp_dastore(u2 len, char *symbol, void *base);
int jvm_interp_aastore(u2 len, char *symbol, void *base);
int jvm_interp_bastore(u2 len, char *symbol, void *base);
int jvm_interp_castore(u2 len, char *symbol, void *base);
int jvm_interp_sastore(u2 len, char *symbol, void *base);
int jvm_interp_pop(u2 len, char *symbol, void *base);
int jvm_interp_pop2(u2 len, char *symbol, void *base);
int jvm_interp_dup(u2 len, char *symbol, void *base);
int jvm_interp_dup_x1(u2 len, char *symbol, void *base);
int jvm_interp_dup_x2(u2 len, char *symbol, void *base);
int jvm_interp_dup2(u2 len, char *symbol, void *base);
int jvm_interp_dup2_x1(u2 len, char *symbol, void *base);
int jvm_interp_dup2_x2(u2 len, char *symbol, void *base);
int jvm_interp_swap(u2 len, char *symbol, void *base);
int jvm_interp_iadd(u2 len, char *symbol, void *base);
int jvm_interp_ladd(u2 len, char *symbol, void *base);
int jvm_interp_fadd(u2 len, char *symbol, void *base);
int jvm_interp_dadd(u2 len, char *symbol, void *base);
int jvm_interp_isub(u2 len, char *symbol, void *base);
int jvm_interp_lsub(u2 len, char *symbol, void *base);
int jvm_interp_fsub(u2 len, char *symbol, void *base);
int jvm_interp_dsub(u2 len, char *symbol, void *base);
int jvm_interp_imul(u2 len, char *symbol, void *base);
int jvm_interp_lmul(u2 len, char *symbol, void *base);
int jvm_interp_fmul(u2 len, char *symbol, void *base);
int jvm_interp_dmul(u2 len, char *symbol, void *base);
int jvm_interp_idiv(u2 len, char *symbol, void *base);
int jvm_interp_ldiv(u2 len, char *symbol, void *base);
int jvm_interp_fdiv(u2 len, char *symbol, void *base);
int jvm_interp_ddiv(u2 len, char *symbol, void *base);
int jvm_interp_irem(u2 len, char *symbol, void *base);
int jvm_interp_lrem(u2 len, char *symbol, void *base);
int jvm_interp_frem(u2 len, char *symbol, void *base);
int jvm_interp_drem(u2 len, char *symbol, void *base);
int jvm_interp_ineg(u2 len, char *symbol, void *base);
int jvm_interp_lneg(u2 len, char *symbol, void *base);
int jvm_interp_fneg(u2 len, char *symbol, void *base);
int jvm_interp_dneg(u2 len, char *symbol, void *base);
int jvm_interp_ishl(u2 len, char *symbol, void *base);
int jvm_interp_lshl(u2 len, char *symbol, void *base);
int jvm_interp_ishr(u2 len, char *symbol, void *base);
int jvm_interp_lshr(u2 len, char *symbol, void *base);
int jvm_interp_iushr(u2 len, char *symbol, void *base);
int jvm_interp_lushr(u2 len, char *symbol, void *base);
int jvm_interp_iand(u2 len, char *symbol, void *base);
int jvm_interp_land(u2 len, char *symbol, void *base);
int jvm_interp_ior(u2 len, char *symbol, void *base);
int jvm_interp_lor(u2 len, char *symbol, void *base);
int jvm_interp_ixor(u2 len, char *symbol, void *base);
int jvm_interp_lxor(u2 len, char *symbol, void *base);
int jvm_interp_iinc(u2 len, char *symbol, void *base);
int jvm_interp_i2l(u2 len, char *symbol, void *base);
int jvm_interp_i2f(u2 len, char *symbol, void *base);
int jvm_interp_i2d(u2 len, char *symbol, void *base);
int jvm_interp_l2i(u2 len, char *symbol, void *base);
int jvm_interp_l2f(u2 len, char *symbol, void *base);
int jvm_interp_l2d(u2 len, char *symbol, void *base);
int jvm_interp_f2i(u2 len, char *symbol, void *base);
int jvm_interp_f2l(u2 len, char *symbol, void *base);
int jvm_interp_f2d(u2 len, char *symbol, void *base);
int jvm_interp_d2i(u2 len, char *symbol, void *base);
int jvm_interp_d2l(u2 len, char *symbol, void *base);
int jvm_interp_d2f(u2 len, char *symbol, void *base);
int jvm_interp_i2b(u2 len, char *symbol, void *base);
int jvm_interp_i2c(u2 len, char *symbol, void *base);
int jvm_interp_i2s(u2 len, char *symbol, void *base);
int jvm_interp_lcmp(u2 len, char *symbol, void *base);
int jvm_interp_fcmpl(u2 len, char *symbol, void *base);
int jvm_interp_fcmpg(u2 len, char *symbol, void *base);
int jvm_interp_dcmpl(u2 len, char *symbol, void *base);
int jvm_interp_dcmpg(u2 len, char *symbol, void *base);
int jvm_interp_ifeq(u2 len, char *symbol, void *base);
int jvm_interp_ifne(u2 len, char *symbol, void *base);
int jvm_interp_iflt(u2 len, char *symbol, void *base);
int jvm_interp_ifge(u2 len, char *symbol, void *base);
int jvm_interp_ifgt(u2 len, char *symbol, void *base);
int jvm_interp_ifle(u2 len, char *symbol, void *base);
int jvm_interp_if_icmpeq(u2 len, char *symbol, void *base);
int jvm_interp_if_icmpne(u2 len, char *symbol, void *base);
int jvm_interp_if_icmplt(u2 len, char *symbol, void *base);
int jvm_interp_if_icmpge(u2 len, char *symbol, void *base);
int jvm_interp_if_icmpgt(u2 len, char *symbol, void *base);
int jvm_interp_if_icmple(u2 len, char *symbol, void *base);
int jvm_interp_if_acmpeq(u2 len, char *symbol, void *base);
int jvm_interp_if_acmpne(u2 len, char *symbol, void *base);
int jvm_interp_goto(u2 len, char *symbol, void *base);
int jvm_interp_jsr(u2 len, char *symbol, void *base);
int jvm_interp_ret(u2 len, char *symbol, void *base);
int jvm_interp_tableswitch(u2 len, char *symbol, void *base);
int jvm_interp_lookupswitch(u2 len, char *symbol, void *base);
int jvm_interp_ireturn(u2 len, char *symbol, void *base);
int jvm_interp_lreturn(u2 len, char *symbol, void *base);
int jvm_interp_freturn(u2 len, char *symbol, void *base);
int jvm_interp_dreturn(u2 len, char *symbol, void *base);
int jvm_interp_areturn(u2 len, char *symbol, void *base);
int jvm_interp_return(u2 len, char *symbol, void *base);
int jvm_interp_getstatic(u2 len, char *symbol, void *base);
int jvm_interp_putstatic(u2 len, char *symbol, void *base);
int jvm_interp_getfiled(u2 len, char *symbol, void *base);
int jvm_interp_putfiled(u2 len, char *symbol, void *base);
int jvm_interp_invokevirtual(u2 len, char *symbol, void *base);
int jvm_interp_invokespecial(u2 len, char *symbol, void *base);
int jvm_interp_invokestatic(u2 len, char *symbol, void *base);
int jvm_interp_invokeinterface(u2 len, char *symbol, void *base);
int jvm_interp_invokedynamic(u2 len, char *symbol, void *base);
int jvm_interp_new(u2 len, char *symbol, void *base);
int jvm_interp_newarray(u2 len, char *symbol, void *base);
int jvm_interp_anewarray(u2 len, char *symbol, void *base);
int jvm_interp_arraylength(u2 len, char *symbol, void *base);
int jvm_interp_athrow(u2 len, char *symbol, void *base);
int jvm_interp_checkcast(u2 len, char *symbol, void *base);
int jvm_interp_instanceof(u2 len, char *symbol, void *base);
int jvm_interp_monitorenter(u2 len, char *symbol, void *base);
int jvm_interp_monitorexit(u2 len, char *symbol, void *base);
int jvm_interp_wide(u2 len, char *symbol, void *base);
int jvm_interp_multianewarray(u2 len, char *symbol, void *base);
int jvm_interp_ifnull(u2 len, char *symbol, void *base);
int jvm_interp_ifnonnull(u2 len, char *symbol, void *base);
int jvm_interp_goto_w(u2 len, char *symbol, void *base);
int jvm_interp_jsr_w(u2 len, char *symbol, void *base);
int jvm_interp_getfield(u2 len, char *symbol, void *base);
int jvm_interp_putfield(u2 len, char *symbol, void *base);

int disass_bytecode(struct list_head *list_head);

BYTECODE jvm_byte_code[OPCODE_LEN] = {
                {0x00,  1,      "nop",          	jvm_interp_nop},
                {0x01,  1,      "aconst_null",          jvm_interp_aconst_null},
                {0x02,  1,      "iconst_m1",            jvm_interp_iconst_m1},
                {0x03,  1,      "iconst_0",             jvm_interp_iconst_0},
                {0x04,  1,      "iconst_1",             jvm_interp_iconst_1},
                {0x05,  1,      "iconst_2",             jvm_interp_iconst_2},
                {0x06,  1,      "iconst_3",             jvm_interp_iconst_3},
                {0x07,  1,      "iconst_4",             jvm_interp_iconst_4},
                {0x08,  1,      "iconst_5",             jvm_interp_iconst_5},
                {0x09,  1,      "lconst_0",             jvm_interp_lconst_0},
                {0x0a,  1,      "lconst_1",             jvm_interp_lconst_1},
                {0x0b,  1,      "fconst_0",             jvm_interp_fconst_0},
                {0x0c,  1,      "fconst_1",             jvm_interp_fconst_1},
                {0x0d,  1,      "fconst_2",             jvm_interp_fconst_2},
                {0x0e,  1,      "dconst_0",             jvm_interp_dconst_0},
                {0x0f,  1,      "dconst_1",             jvm_interp_dconst_1},
                {0x10,  2,      "bipush",               jvm_interp_bipush},
                {0x11,  3,      "sipush",               jvm_interp_sipush},
                {0x12,  2,      "ldc",          	jvm_interp_ldc},
                {0x13,  1,      "ldc_w",                jvm_interp_ldc_w},
                {0x14,  3,      "ldc2_w",               jvm_interp_ldc2_w},
                {0x15,  2,      "iload",                jvm_interp_iload},
                {0x16,  2,      "lload",                jvm_interp_lload},
                {0x17,  2,      "fload",                jvm_interp_fload},
                {0x18,  2,      "dload",                jvm_interp_dload},
                {0x19,  2,      "aload",                jvm_interp_aload},
                {0x1a,  1,      "iload_0",              jvm_interp_iload_0},
                {0x1b,  1,      "iload_1",              jvm_interp_iload_1},
                {0x1c,  1,      "iload_2",              jvm_interp_iload_2},
                {0x1d,  1,      "iload_3",              jvm_interp_iload_3},
                {0x1e,  1,      "lload_0",              jvm_interp_lload_0},
                {0x1f,  1,      "lload_1",              jvm_interp_lload_1},
                {0x20,  1,      "lload_2",              jvm_interp_lload_2},
                {0x21,  1,      "lload_3",              jvm_interp_lload_3},
                {0x22,  1,      "fload_0",              jvm_interp_fload_0},
                {0x23,  1,      "fload_1",              jvm_interp_fload_1},
                {0x24,  1,      "fload_2",              jvm_interp_fload_2},
                {0x25,  1,      "fload_3",              jvm_interp_fload_3},
                {0x26,  1,      "dload_0",              jvm_interp_dload_0},
                {0x27,  1,      "dload_1",              jvm_interp_dload_1},
                {0x28,  1,      "dload_2",              jvm_interp_dload_2},
                {0x29,  1,      "dload_3",              jvm_interp_dload_3},
                {0x2a,  1,      "aload_0",              jvm_interp_aload_0},
                {0x2b,  1,      "aload_1",              jvm_interp_aload_1},
                {0x2c,  1,      "aload_2",              jvm_interp_aload_2},
                {0x2d,  1,      "aload_3",              jvm_interp_aload_3},
                {0x2e,  1,      "iaload",               jvm_interp_iaload},
                {0x2f,  1,      "laload",               jvm_interp_laload},
                {0x30,  1,      "faload",               jvm_interp_faload},
                {0x31,  1,      "daload",               jvm_interp_daload},
                {0x32,  1,      "aaload",               jvm_interp_aaload},
                {0x33,  1,      "baload",               jvm_interp_baload},
                {0x34,  1,      "caload",               jvm_interp_caload},
                {0x35,  1,      "saload",               jvm_interp_saload},
                {0x36,  2,      "istore",               jvm_interp_istore},
                {0x37,  2,      "lstore",               jvm_interp_lstore},
                {0x38,  2,      "fstore",               jvm_interp_fstore},
                {0x39,  2,      "dstore",               jvm_interp_dstore},
                {0x3a,  2,      "astore",               jvm_interp_astore},
                {0x3b,  1,      "istore_0",             jvm_interp_istore_0},
                {0x3c,  1,      "istore_1",             jvm_interp_istore_1},
                {0x3d,  1,      "istore_2",             jvm_interp_istore_2},
                {0x3e,  1,      "istore_3",             jvm_interp_istore_3},
                {0x3f,  1,      "lstore_0",             jvm_interp_lstore_0},
                {0x40,  1,      "lstore_1",             jvm_interp_lstore_1},
                {0x41,  1,      "lstore_2",             jvm_interp_lstore_2},
                {0x42,  1,      "lstore_3",             jvm_interp_lstore_3},
                {0x43,  1,      "fstore_0",             jvm_interp_fstore_0},
                {0x44,  1,      "fstore_1",             jvm_interp_fstore_1},
                {0x45,  1,      "fstore_2",             jvm_interp_fstore_2},
                {0x46,  1,      "fstore_3",             jvm_interp_fstore_3},
                {0x47,  1,      "dstore_0",             jvm_interp_dstore_0},
                {0x48,  1,      "dstore_1",             jvm_interp_dstore_1},
                {0x49,  1,      "dstore_2",             jvm_interp_dstore_2},
                {0x4a,  1,      "dstore_3",             jvm_interp_dstore_3},
                {0x4b,  1,      "astore_0",             jvm_interp_astore_0},
                {0x4c,  1,      "astore_1",             jvm_interp_astore_1},
                {0x4d,  1,      "astore_2",             jvm_interp_astore_2},
                {0x4e,  1,      "astore_3",             jvm_interp_astore_3},
                {0x4f,  1,      "iastore",              jvm_interp_iastore},
                {0x50,  1,      "lastore",              jvm_interp_lastore},
                {0x51,  1,      "fastore",              jvm_interp_fastore},
                {0x52,  1,      "dastore",              jvm_interp_dastore},
                {0x53,  1,      "aastore",              jvm_interp_aastore},
                {0x54,  1,      "bastore",              jvm_interp_bastore},
                {0x55,  1,      "castore",              jvm_interp_castore},
                {0x56,  1,      "sastore",              jvm_interp_sastore},
                {0x57,  1,      "pop",          	jvm_interp_pop},
                {0x58,  1,      "pop2",         	jvm_interp_pop2},
                {0x59,  1,      "dup",          	jvm_interp_dup},
                {0x5a,  1,      "dup_x1",               jvm_interp_dup_x1},
                {0x5b,  1,      "dup_x2",               jvm_interp_dup_x2},
                {0x5c,  1,      "dup2",         	jvm_interp_dup2},
                {0x5d,  1,      "dup2_x1",              jvm_interp_dup2_x1},
                {0x5e,  1,      "dup2_x2",              jvm_interp_dup2_x2},
                {0x5f,  1,      "swap",         jvm_interp_swap},
                {0x60,  1,      "iadd",         jvm_interp_iadd},
                {0x61,  1,      "ladd",         jvm_interp_ladd},
                {0x62,  1,      "fadd",         jvm_interp_fadd},
                {0x63,  1,      "dadd",         jvm_interp_dadd},
                {0x64,  1,      "isub",         jvm_interp_isub},
                {0x65,  1,      "lsub",         jvm_interp_lsub},
                {0x66,  1,      "fsub",         jvm_interp_fsub},
                {0x67,  1,      "dsub",         jvm_interp_dsub},
                {0x68,  1,      "imul",         jvm_interp_imul},
                {0x69,  1,      "lmul",         jvm_interp_lmul},
                {0x6a,  1,      "fmul",         jvm_interp_fmul},
                {0x6b,  1,      "dmul",         jvm_interp_dmul},
                {0x6c,  1,      "idiv",         jvm_interp_idiv},
                {0x6d,  1,      "ldiv",         jvm_interp_ldiv},
                {0x6e,  1,      "fdiv",         jvm_interp_fdiv},
                {0x6f,  1,      "ddiv",         jvm_interp_ddiv},
                {0x70,  1,      "irem",         jvm_interp_irem},
                {0x71,  1,      "lrem",         jvm_interp_lrem},
                {0x72,  1,      "frem",         jvm_interp_frem},
                {0x73,  1,      "drem",         jvm_interp_drem},
                {0x74,  1,      "ineg",         jvm_interp_ineg},
                {0x75,  1,      "lneg",         jvm_interp_lneg},
                {0x76,  1,      "fneg",         jvm_interp_fneg},
                {0x77,  1,      "dneg",         jvm_interp_dneg},
                {0x78,  1,      "ishl",         jvm_interp_ishl},
                {0x79,  1,      "lshl",         	jvm_interp_lshl},
                {0x7a,  1,      "ishr",         	jvm_interp_ishr},
                {0x7b,  1,      "lshr",         	jvm_interp_lshr},
                {0x7c,  1,      "iushr",                jvm_interp_iushr},
                {0x7d,  1,      "lushr",                jvm_interp_lushr},
                {0x7e,  1,      "iand",         jvm_interp_iand},
                {0x7f,  1,      "land",         jvm_interp_land},
                {0x80,  1,      "ior",          jvm_interp_ior},
                {0x81,  1,      "lor",          jvm_interp_lor},
                {0x82,  1,      "ixor",         jvm_interp_ixor},
                {0x83,  1,      "lxor",         jvm_interp_lxor},
                {0x84,  3,      "iinc",         jvm_interp_iinc},
                {0x85,  1,      "i2l",          jvm_interp_i2l},
                {0x86,  1,      "i2f",          jvm_interp_i2f},
                {0x87,  1,      "i2d",          jvm_interp_i2d},
                {0x88,  1,      "l2i",          jvm_interp_l2i},
                {0x89,  1,      "l2f",          jvm_interp_l2f},
                {0x8a,  1,      "l2d",          jvm_interp_l2d},
                {0x8b,  1,      "f2i",          jvm_interp_f2i},
                {0x8c,  1,      "f2l",          jvm_interp_f2l},
                {0x8d,  1,      "f2d",          jvm_interp_f2d},
                {0x8e,  1,      "d2i",          jvm_interp_d2i},
                {0x8f,  1,      "d2l",          jvm_interp_d2l},
                {0x90,  1,      "d2f",          jvm_interp_d2f},
                {0x91,  1,      "i2b",          jvm_interp_i2b},
                {0x92,  1,      "i2c",          jvm_interp_i2c},
                {0x93,  1,      "i2s",          jvm_interp_i2s},
                {0x94,  1,      "lcmp",         jvm_interp_lcmp},
                {0x95,  1,      "fcmpl",                jvm_interp_fcmpl},
                {0x96,  1,      "fcmpg",                jvm_interp_fcmpg},
                {0x97,  1,      "dcmpl",                jvm_interp_dcmpl},
                {0x98,  1,      "dcmpg",                jvm_interp_dcmpg},
                {0x99,  1,      "ifeq",         	jvm_interp_ifeq},
                {0x9a,  1,      "ifne",         	jvm_interp_ifne},
                {0x9b,  1,      "iflt",         	jvm_interp_iflt},
                {0x9c,  1,      "ifge",         	jvm_interp_ifge},
                {0x9d,  1,      "ifgt",         	jvm_interp_ifgt},
                {0x9e,  1,      "ifle",         	jvm_interp_ifle},
                {0x9f,  3,      "if_icmpeq",            jvm_interp_if_icmpeq},
                {0xa0,  3,      "if_icmpne",            jvm_interp_if_icmpne},
                {0xa1,  3,      "if_icmplt",            jvm_interp_if_icmplt},
                {0xa2,  3,      "if_icmpge",            jvm_interp_if_icmpge},
                {0xa3,  3,      "if_icmpgt",            jvm_interp_if_icmpgt},
                {0xa4,  3,      "if_icmple",            jvm_interp_if_icmple},
                {0xa5,  1,      "if_acmpeq",            jvm_interp_if_acmpeq},
                {0xa6,  1,      "if_acmpne",            jvm_interp_if_acmpne},
                {0xa7,  3,      "goto",         	jvm_interp_goto},
                {0xa8,  1,      "jsr",          	jvm_interp_jsr},
                {0xa9,  1,      "ret",          	jvm_interp_ret},
                {0xaa,  1,      "tableswitch",          jvm_interp_tableswitch},
                {0xab,  1,      "lookupswitch",         jvm_interp_lookupswitch},
                {0xac,  1,      "ireturn",              jvm_interp_ireturn},
                {0xad,  1,      "lreturn",              jvm_interp_lreturn},
                {0xae,  1,      "freturn",              jvm_interp_freturn},
                {0xaf,  1,      "dreturn",              jvm_interp_dreturn},
                {0xb0,  1,      "areturn",              jvm_interp_areturn},
                {0xb1,  1,      "return",               jvm_interp_return},
                {0xb2,  3,      "getstatic",            jvm_interp_getstatic},
                {0xb3,  3,      "putstatic",            jvm_interp_putstatic},
                {0xb4,  3,      "getfield",             jvm_interp_getfiled},
                {0xb5,  3,      "putfield",             jvm_interp_putfiled},
                {0xb6,  3,      "invokevirtual",        jvm_interp_invokevirtual},
                {0xb7,  3,      "invokespecial",        jvm_interp_invokespecial},
                {0xb8,  3,      "invokestatic",         jvm_interp_invokestatic},
                {0xb9,  3,      "invokeinterface",      jvm_interp_invokeinterface},
                {0xba,  3,      "invokedynamic",        jvm_interp_invokedynamic},
                {0xbb,  3,      "new",          	jvm_interp_new},
                {0xbc,  1,      "newarray",             jvm_interp_newarray},
                {0xbd,  1,      "anewarray",            jvm_interp_anewarray},
                {0xbe,  1,      "arraylength",          jvm_interp_arraylength},
                {0xbf,  1,      "athrow",               jvm_interp_athrow},
                {0xc0,  1,      "checkcast",            jvm_interp_checkcast},
                {0xc1,  1,      "instanceof",           jvm_interp_instanceof},
                {0xc2,  1,      "monitorenter",         jvm_interp_monitorenter},
                {0xc3,  1,      "monitorexit",          jvm_interp_monitorexit},
                {0xc4,  1,      "wide",         	jvm_interp_wide},
                {0xc5,  1,      "multianewarray",       jvm_interp_multianewarray},
                {0xc6,  1,      "ifnull",               jvm_interp_ifnull},
                {0xc7,  1,      "ifnonnull",            jvm_interp_ifnonnull},
                {0xc8,  1,      "goto_w",               jvm_interp_goto_w},
                {0xc9,  1,      "jsr_w",               	jvm_interp_jsr_w},
		};
#endif
