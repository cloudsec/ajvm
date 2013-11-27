#ifndef SAFE_PRINTF_H
#define SAFE_PRINTF_H

typedef struct func_arg {
        long arg[6];
        long va_arg;
        int arg_idx;
}FUNC_ARG;

#define INIT_ARG(func_arg)                                                      \
        do {                                                                    \
                func_arg.arg_idx = 1;                                           \
        } while (0);

#define GET_ARG(func_arg)                                                       \
        do {                                                                    \
                asm("movq %%rdi, %0":"=r"(func_arg.arg[0]));                    \
                asm("movq %%rsi, %0":"=r"(func_arg.arg[1]));                    \
                asm("movq %%rdx, %0":"=r"(func_arg.arg[2]));                    \
                asm("movq %%rcx, %0":"=r"(func_arg.arg[3]));                    \
                asm("movq %%r8, %0":"=r"(func_arg.arg[4]));                     \
                asm("movq %%r9, %0":"=r"(func_arg.arg[5]));                     \
        } while (0);

#define VA_START_ARG(func_arg)                                                  \
        do {                                                                    \
                asm("movq %%rbp, %%rax\n\t"                                     \
                        "addq $0x10, %%rax\n\t"                                 \
                        "movq %%rax, %0":"=r"(func_arg.va_arg));                \
        } while (0);

#define VA_NEXT_ARG(value, func_arg, type)                                      \
        do {                                                                    \
                if (func_arg.arg_idx <= 5) {                                    \
                        value = (type)func_arg.arg[func_arg.arg_idx++];         \
                }                                                               \
                else {                                                          \
                        value = *(type *)(func_arg.va_arg);                     \
                        func_arg.va_arg += sizeof(long);                        \
                }                                                               \
        } while (0);

void safe_printf(const char *fmt, ...);

#endif
