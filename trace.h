#ifndef TRACE_H
#define TRACE_H

#define X86_64

#define MAX_TRACE_NUM           128

#define GET_BP(x)               asm("movq %%rbp, %0":"=r"(x));

typedef struct trace_st {
        unsigned long rip;
        char *symbol_name;
        unsigned long symbol_addr;
        unsigned int offset;
        unsigned int size;
}CALL_TRACE;

unsigned long *top_bp;
void calltrace(void);
void calltrace_gnu(void);
void show_calltrace(CALL_TRACE *trace);

#endif
