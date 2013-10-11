#ifndef TRACE_H
#define TRACE_H

#include <stdlib.h>

//#define GCC_BUILTIN_ADDRESS

#if __WORDSIZE == 64
#ifdef GCC_BUILTIN_ADDRESS					
#define GET_TOP_RBP(rbp) do {							  \
				rbp = (unsigned long *)__builtin_frame_address(0);\
			} while(0);						
#else								
#define GET_TOP_RBP(rbp) do {							\
				asm("movq %%rbp, %0":"=r"(rbp));		\			
			} while (0);					
#endif								


#define GET_BP(x)      		asm("movq %%rbp, %0":"=r"(x));
#define GET_SP(x)      		asm("movq %%rsp, %0":"=r"(x));
#define GET_AX(x)      		asm("movq %%rax, %0":"=r"(x));
#define GET_BX(x)      		asm("movq %%rbx, %0":"=r"(x));
#define GET_CX(x)      		asm("movq %%rcx, %0":"=r"(x));
#define GET_DX(x)      		asm("movq %%rdx, %0":"=r"(x));
#define GET_SI(x)      		asm("movq %%rsi, %0":"=r"(x));
#define GET_DI(x)      		asm("movq %%rdi, %0":"=r"(x));
#define GET_R8(x)      		asm("movq %%r8, %0":"=r"(x));
#define GET_R9(x)      		asm("movq %%r9, %0":"=r"(x));
#define GET_R10(x)    		asm("movq %%r10, %0":"=r"(x));
#define GET_R11(x)     		asm("movq %%r11, %0":"=r"(x));
#define GET_R12(x)     		asm("movq %%r12, %0":"=r"(x));
#define GET_R13(x)     		asm("movq %%r13, %0":"=r"(x));
#define GET_R14(x)     		asm("movq %%r14, %0":"=r"(x));
#define GET_R15(x)     		asm("movq %%r15, %0":"=r"(x));

#else
#ifdef GCC_BUILTIN_ADDRESS					
#define GET_TOP_EBP(ebp) do {							  \
				ebp = (unsigned long *)__builtin_frame_address(0);\
			} while(0);						
#else								
#define GET_TOP_EBP(rbp) do {							\
				asm("movq %%ebp, %0":"=r"(ebp));		\			
			} while (0);					
#endif								

#define GET_BP(x)      		asm("movl %%ebp, %0":"=r"(x));
#define GET_SP(x)      		asm("movl %%esp, %0":"=r"(x));
#define GET_AX(x)      		asm("movl %%eax, %0":"=r"(x));
#define GET_BX(x)      		asm("movl %%ebx, %0":"=r"(x));
#define GET_CX(x)      		asm("movl %%ecx, %0":"=r"(x));
#define GET_DX(x)      		asm("movl %%edx, %0":"=r"(x));
#define GET_SI(x)      		asm("movl %%esi, %0":"=r"(x));
#define GET_DI(x)      		asm("movl %%edi, %0":"=r"(x));

#endif

typedef struct trace_st {
	unsigned long rip;
	char *symbol_name;
	unsigned long symbol_addr;
	unsigned int offset;
        unsigned int size;
}CALL_TRACE;

unsigned long *top_rbp;
void calltrace(void);
void calltrace_gnu(void);
void show_calltrace(CALL_TRACE *trace);
int search_symbol_by_addr(unsigned long addr, CALL_TRACE *trace);
int load_elf_symbols(char *elf_file);
void get_top_rbp(void);
int calltrace_init(void);
void calltrace_exit(void);

#endif
