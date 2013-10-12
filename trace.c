/*
 * trace.c (c) 2012, 2013 wzt	http://www.cloud-sec.org
 *
 * use bp register pointer to compute function call chain.
 *
 * XXX: Doesn't work with gcc option -fomit-frame-pointer or -O2.
 *
 * --------stack call trace frame map-----------
 *
 *
 *         |...|
 *         |rbp|<--|   push rbp; mov rsp, rbp
 * ctrace->|rip|   |   call calltrace + 1
 *         |...|   |
 *         |rbp|<--|   push rbp; mov rsp, rbp
 * test2-> |rip|   |   call test2 + 1
 *         |...|   |
 *         |rbp|<--|   push rbp; mov rsp, rbp
 * test1-> |rip|   |   call test1 + 1
 *         |...|   |
 *         |rbp|<--|   push rbp; mov rsp, rbp
 * test->  |rip|   |   call test + 1
 *         |...|   |
 *         |rbp|<--|   push rbp; mov rsp, rbp
 * main->  |rip|   |   call main + 1
 *         |...|   |
 * glibc   |...|<--|   rbp->unkonwn  
 *
 *
 *
 * ---------SIGSEGV single handler frame map----------
 *
 *         |...|
 *         |rbp|<--|   push rbp; mov rsp, rbp
 * do_sig->|eip|   |   unkown
 *         |...|<----- segfault
 *         |...|
 *         |rbp|<--|   push rbp; mov rsp, rbp
 * test2-> |rip|   |   call test2 + 1
 *         |...|   |
 *         |rbp|<--|   push rbp; mov rsp, rbp
 * test1-> |rip|   |   call test1 + 1
 *         |...|   |
 *         |rbp|<--|   push rbp; mov rsp, rbp
 * test->  |rip|   |   call test + 1
 *         |...|   |
 *         |rbp|<--|   push rbp; mov rsp, rbp
 * main->  |rip|   |   call main + 1
 *         |...|   |
 * glibc   |...|<--|   rbp->unkonwn  
 *
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
#include <signal.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <execinfo.h>

#define __USE_GNU
#include <ucontext.h>

#include "trace.h"
#include "log.h"

void safe_printf(char *fmt, ...)
{
        va_list arg;
        char buf[1024];

        va_start(arg, fmt);
        vsprintf(buf, fmt, arg);
        va_end(arg);

	write(1, buf, strlen(buf) + 1);
}

#if __WORDSIZE == 64
void show_stack(ucontext_t *uc)
{
        int i;
        uint64_t rsp, rbp;

	rsp = uc->uc_mcontext.gregs[REG_RSP];
	rbp = uc->uc_mcontext.gregs[REG_RBP];

        safe_printf("Stack:\t\t\nrsp: 0x%016x\t\trbp: 0x%016x\n", rsp, rbp);
        for (i = 0; i < 16; i++) {
                safe_printf("0x%02x ", *((unsigned char *)rsp + i));
        }
        safe_printf("\n\n");
}

void show_registers(ucontext_t *uc)
{
        uint64_t rax, rbx, rcx, rdx, rsi, rdi;
        uint64_t r9, r10, r11, r12, r13, r14, r15;
	uint64_t rip, cr2;

	rax = uc->uc_mcontext.gregs[REG_RAX];
	rbx = uc->uc_mcontext.gregs[REG_RBX];
	rcx = uc->uc_mcontext.gregs[REG_RCX];
	rdx = uc->uc_mcontext.gregs[REG_RDX];
	rsi = uc->uc_mcontext.gregs[REG_RSI];
	rdi = uc->uc_mcontext.gregs[REG_RDI];
	r9 = uc->uc_mcontext.gregs[REG_R9];
	r10 = uc->uc_mcontext.gregs[REG_R10];
	r11 = uc->uc_mcontext.gregs[REG_R11];
	r12 = uc->uc_mcontext.gregs[REG_R12];
	r13 = uc->uc_mcontext.gregs[REG_R13];
	r14 = uc->uc_mcontext.gregs[REG_R14];
	r15 = uc->uc_mcontext.gregs[REG_R15];
	rip = uc->uc_mcontext.gregs[REG_RIP];
	cr2 = uc->uc_mcontext.gregs[REG_CR2];

        safe_printf("Registers:\n");
	safe_printf("RIP: 0x%016x\t\tCR2: 0x%016x\n\n", rip, cr2);
        safe_printf("rax = 0x%016x, rbx = 0x%016x, rcx = 0x%016x, rdx = 0x%016x\n"
                "rsi = 0x%016x, rdi = 0x%016x, r8 = 0x%016x, r9 = 0x%016x\n"
                "r10 = 0x%016x, r11 = 0x%016x, r12 = 0x%016x, r13 = 0x%016x\n"
                "r14 = 0x%016x, r15 = 0x%016x\n\n",
                rax, rbx, rcx, rdx, rsi, rdi,
                r9, r10, r11, r12, r13, r14, r15);
}
#else
void show_stack(ucontext_t *uc)
{
        int i;
        uint32_t esp, ebp;

	esp = uc->uc_mcontext.gregs[REG_UESP];
	ebp = uc->uc_mcontext.gregs[REG_EBP];

        safe_printf("Stack:\t\t\nesp: 0x%08x\t\tebp: 0x%08x\n", esp, ebp);
        for (i = 0; i < 16; i++) {
                safe_printf("0x%02x ", *((unsigned char *)esp + i));
        }
        safe_printf("\n\n");
}

void show_registers(ucontext_t *uc)
{
        uint32_t rax, rbx, rcx, rdx, rsi, rdi;
	uint32_t rip;

	eax = uc->uc_mcontext.gregs[REG_EAX];
	ebx = uc->uc_mcontext.gregs[REG_EBX];
	ecx = uc->uc_mcontext.gregs[REG_ECX];
	edx = uc->uc_mcontext.gregs[REG_EDX];
	esi = uc->uc_mcontext.gregs[REG_ESI];
	edi = uc->uc_mcontext.gregs[REG_EDI];
	eip = uc->uc_mcontext.gregs[REG_EIP];

        safe_printf("Registers:\n");
	safe_printf("EIP: 0x%08x\n\n", eip);
        safe_printf("eax = 0x%08x, ebx = 0x%08x, ecx = 0x%08x, edx = 0x%08x\n"
                "esi = 0x%08x, edi = 0x%08x\n"
                rax, rbx, rcx, rdx, rsi, rdi);
}
#endif

unsigned long compute_real_func_addr(unsigned long rip)
{
	unsigned long func_addr = 0;
	unsigned long offset = 0;

	offset = *(unsigned long *)(rip - 4);
	func_addr = offset + rip;

	return func_addr;
}

void segfault_handler(int sig_num, siginfo_t *sig_info, void *ptr)
{
        CALL_TRACE trace, prev_trace;
	ucontext_t *uc = (ucontext_t *)ptr;
        unsigned long *rbp, rip, real_rip;
        int flag = 0, first_bp = 0;

        assert(sig_info != NULL);
        safe_printf("\n#Pid: %d segfault at addr: 0x%016x\tsi_signo: %d\tsi_errno: %d\n\n",
                getpid(), sig_info->si_addr,
                sig_info->si_signo, sig_info->si_errno);

        show_registers(uc);
        show_stack(uc);

        safe_printf("Call trace:\n\n");

#ifdef GCC_BUILTIN_ADDRESS
        rbp = (unsigned long *)__builtin_frame_address(1);
#else
        GET_BP(rbp)
#endif
        while (rbp != top_rbp) {
                rip = *(unsigned long *)(rbp + 1);
                rbp = (unsigned long *)*rbp;
                real_rip = compute_real_func_addr(rip);

                if (flag == 1) {
                        if (search_symbol_by_addr(real_rip, &prev_trace) == -1) {
                                __debug2("calltrace: search symbol failed.");
				continue;
                        }

                        prev_trace.rip = rip - 5;
                        if (first_bp == 0) {
                                first_bp = 1;
                                prev_trace.offset = 0;
                        }
                        else {
                                prev_trace.offset = trace.rip - prev_trace.symbol_addr;
                        }
                        show_calltrace(&prev_trace);

                        trace = prev_trace;
                }
                else {
                        /* it's in a single handler function, the last call frame is unkown,
                         * we can't locate the rip addr. */
                        search_symbol_by_addr(real_rip, &trace);
                        trace.rip = rip - 5;
                        flag = 1;
                }
        }
        safe_printf("\n");

        exit(0);
}

void segfault_handler_gnu(int sig_num, siginfo_t *sig_info, void *ptr)
{
        CALL_TRACE trace, prev_trace;
        ucontext_t *uc = (ucontext_t *)ptr;
        void *addr[32];
        unsigned long real_rip;
        int i, num;
        int flag = 0, first_bp = 0;

        assert(sig_info != NULL);
        safe_printf("\n#Pid: %d segfault at addr: 0x%016x\tsi_signo: %d\tsi_errno: %d\n\n",
                getpid(), sig_info->si_addr,
                sig_info->si_signo, sig_info->si_errno);

        show_registers(uc);
        show_stack(uc);

        safe_printf("Call trace:\n\n");
        num = backtrace(addr, 32);
	addr[1] = (unsigned long *)uc->uc_mcontext.gregs[REG_RIP];

        for (i = 1; i < num; i++) {
                //printf("0x%016x\n", addr[i]);
                real_rip = compute_real_func_addr((unsigned long)addr[i]);

                if (flag == 1) {
                        if (search_symbol_by_addr(real_rip, &prev_trace) == -1) {
                                __debug2("search symbol failed: 0x%x", real_rip);
                                continue;
                        }

                        prev_trace.rip = (unsigned long)addr[i] - 5;
                        prev_trace.offset = trace.rip - prev_trace.symbol_addr;
                        show_calltrace(&prev_trace);

                        trace = prev_trace;
                }
                else {
                        if (search_symbol_by_addr(real_rip, &trace) == -1) {
                                __debug2("search symbol failed: 0x%x", real_rip);
                                //continue;
                        }
                        /* the rip generate segfault. */
                        trace.rip = (unsigned long)addr[i] - 5;
                        flag = 1;
                }
        }
        safe_printf("\n");

	exit(0);
}

void calltrace(void)
{
	CALL_TRACE trace, prev_trace;
	unsigned long *rbp, rip, real_rip;
	int flag = 0;

	printf("Call trace:\n\n");

#ifdef GCC_BUILTIN_ADDRESS
	rbp = (unsigned long *)__builtin_frame_address(0);
#else
	GET_BP(rbp)
#endif

	while (rbp != top_rbp) {
		rip = *(unsigned long *)(rbp + 1);
		rbp = (unsigned long *)*rbp;
		real_rip = compute_real_func_addr(rip);

		__debug2("0x%lx\t0x%x\t0x%x\n", rbp, rip, real_rip);
		if (flag == 1) {
			if (search_symbol_by_addr(real_rip, &prev_trace) == -1) {
				__error("search symbol failed: 0x%x", real_rip);
				continue;
			}

			prev_trace.rip = rip - 5;
			prev_trace.offset = trace.rip - prev_trace.symbol_addr;
			show_calltrace(&prev_trace);

			trace = prev_trace;
		}
		else {
			if (search_symbol_by_addr(real_rip, &trace) == -1) {
				__error("search symbol failed: 0x%x", real_rip);
				//continue;
			}
			/* the rip generate segfault. */
			trace.rip = rip - 5;
			flag = 1;
		}
	}  
	printf("\n");
}

void calltrace_gnu(void)
{
	CALL_TRACE trace, prev_trace;
	void *addr[32];
	unsigned long real_rip;
	int i, num;
	int flag = 0;

	printf("Call trace:\n\n");

	num = backtrace(addr, 32);
	for (i = 0; i < num; i++) {
		real_rip = compute_real_func_addr((unsigned long)addr[i]);
		__debug2("0x%016x\t0x%016x\n", addr[i], real_rip);

		if (flag == 1) {
			if (search_symbol_by_addr(real_rip, &prev_trace) == -1) {
				__debug2("search symbol failed: 0x%016x", real_rip);
				continue;
			}

			prev_trace.rip = (unsigned long)addr[i] - 5;
			prev_trace.offset = trace.rip - prev_trace.symbol_addr;
			show_calltrace(&prev_trace);

			trace = prev_trace;
		}
		else {
			if (search_symbol_by_addr(real_rip, &trace) == -1) {
				__debug2("search symbol failed: 0x%016x", real_rip);
				/* skip the first trace? */
				//continue;
			}
			trace.rip = (unsigned long)addr[i] - 5;
			flag = 1;
		}
	}  
	printf("\n");
}

void show_calltrace(CALL_TRACE *trace)
{
	char buff[1024];

	snprintf(buff, sizeof(buff), "[<0x%x>] %s + 0x%x/0x%x\n", 
			trace->rip, trace->symbol_name, trace->offset, trace->size);
	safe_printf("%s", buff);
}

int get_self_path(char *proc_path, int proc_path_len)
{
	char path[1024];
	int size;

	snprintf(path, sizeof(path), "/proc/%d/exe", getpid());
	size = readlink(path, proc_path, proc_path_len);
	if (size == -1) {
		perror("readlink");
		return -1;
	}
	proc_path[size] = '\0';

	return 0;
}

int signal_init(void)
{
	struct sigaction sa;

	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = segfault_handler_gnu;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGSEGV, &sa, NULL) == -1) {
		perror("sigaction");
		return -1;
	}

	return 0;
}

void get_top_rbp(void)
{
#ifdef GCC_BUILTIN_ADDRESS
        top_rbp = (unsigned long *)__builtin_frame_address(1);
#else
        GET_BP(top_rbp)
#endif
}

//int __attribute__((constructor)) calltrace_init(void)
int calltrace_init(void)
{
	char self_path[1024];

	if (signal_init() == -1)
		return -1;

	get_self_path(self_path, sizeof(self_path));
	if (self_path[0] == '\0')
		return -1;

	if (parse_elf_symbol(self_path) == -1) {
		__error("parse elf symbol failed.");
		return -1;
	}

	return 0; 
}

void calltrace_exit(void)
{
	elf_exit();
}
