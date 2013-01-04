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

#include "trace.h"
#include "log.h"

#define X86_64

#ifdef X86_32
static Elf32_Ehdr *elf_ehdr;
static Elf32_Phdr *elf_phdr;
static Elf32_Shdr *elf_shdr;
static Elf32_Shdr *shstrtab;
static Elf32_Sym *symtab_ptr;
#else
static Elf64_Ehdr *elf_ehdr;
static Elf64_Phdr *elf_phdr;
static Elf64_Shdr *elf_shdr;
static Elf64_Shdr *shstrtab;
static Elf64_Sym *symtab_ptr;
#endif

static char *real_strtab;
static char *strtab_ptr;
static int elf_fd;
static struct stat elf_stat;
static char *strtab_buffer;
static int symtab_num;

uint64_t compute_real_func_addr(uint64_t rip)
{
	uint64_t func_addr = 0;
	uint64_t offset = 0;

	offset = *(uint64_t *)(rip - 4);
	func_addr = offset + rip;

	return func_addr;
}

void signal_handler(int sig_num, siginfo_t *sig_info, void *ptr)
{
        CALL_TRACE trace, prev_trace;
        uint64_t *rbp, rip, real_rip;
        int flag = 0, first_bp = 0;

	assert(sig_info != NULL);
        printf("\nPid: %d segfault at addr: 0x%016x\tsi_signo: %d\tsi_errno: %d\n\n", 
		getpid(), sig_info->si_addr, 
		sig_info->si_signo, sig_info->si_errno);

	show_stack();
	show_registers();

        printf("Call trace:\n\n");
        GET_BP(rbp)
        while (rbp != top_rbp) {
                rip = *(uint64_t *)(rbp + 1);
                rbp = (uint64_t *)*rbp;
                real_rip = compute_real_func_addr(rip);

                if (flag == 1) {
                        if (search_symbol_by_addr(real_rip, &prev_trace) == -1) {
                                __error("calltrace: search symbol failed.");
                                exit(-1);
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
        printf("\n");

	exit(0);
}

void calltrace(void)
{
	CALL_TRACE trace, prev_trace;
	uint64_t *rbp, rip, real_rip;
	int flag = 0, first_bp = 0;

	printf("Call trace:\n\n");
	GET_BP(rbp)
	while (rbp != top_rbp) {
		rip = *(uint64_t *)(rbp + 1);
		rbp = (uint64_t *)*rbp;
		real_rip = compute_real_func_addr(rip);

		if (flag == 1) {
			if (search_symbol_by_addr(real_rip, &prev_trace) == -1) {
				__error("calltrace: search symbol failed.");
				exit(-1);
			}

			prev_trace.rip = rip - 5;
			prev_trace.offset = trace.rip - prev_trace.symbol_addr;
			show_calltrace(&prev_trace);

			trace = prev_trace;
		}
		else {
			if (search_symbol_by_addr(real_rip, &trace) == -1) {
				__error("calltrace: search symbol failed.");
				exit(-1);
			}
			trace.rip = rip - 5;
			flag = 1;
		}
	}  
	printf("\n");
}

int check_elf_header(Elf64_Ehdr *ehdr)
{
	if (ehdr->e_ident[EI_MAG0] != 0x7f
		|| ehdr->e_ident[EI_MAG1] != 'E'
		|| ehdr->e_ident[EI_MAG1] != 'L'
		|| ehdr->e_ident[EI_MAG1] != 'F') {
		return -1;
	}

	return 0;
}

void show_stack(void)
{
	int i;
	uint64_t *rsp, *rbp;

	GET_SP(rsp);
	GET_BP(rbp);
	printf("Stack:\t\t\nrsp: 0x%016x\t\trbp: 0x%016x\n", rsp, rbp);
	for (i = 0; i < 16; i++) {
		printf("0x%02x ", *((unsigned char *)rsp + i));
	}
	printf("\n\n");
}

void show_registers(void)
{
	uint64_t rax, rbx, rcx, rdx, rsi, rdi;
	uint64_t r9, r10, r11, r12, r13, r14, r15;

	GET_AX(rax)
	GET_BX(rbx)
	GET_CX(rcx)
	GET_DX(rdx)
	GET_SI(rsi)
	GET_DI(rdi)
	GET_R9(r9)
	GET_R10(r10)
	GET_R11(r11)
	GET_R12(r12)
	GET_R13(r13)
	GET_R14(r14)
	GET_R15(r15)
	printf("Registers:\n");
	printf("rax = 0x%016x, rbx = 0x%016x, rcx = 0x%016x, rdx = 0x%016x\n"
		"rsi = 0x%016x, rdi = 0x%016x, r8 = 0x%016x, r9 = 0x%016x\n"
		"r10 = 0x%016x, r11 = 0x%016x, r12 = 0x%016x, r13 = 0x%016x\n"
		"r14 = 0x%016x, r15 = 0x%016x\n\n", 
		rax, rbx, rcx, rdx, rsi, rdi,
		r9, r10, r11, r12, r13, r14, r15);
}

void show_calltrace(CALL_TRACE *trace)
{
	char buff[1024];

	snprintf(buff, sizeof(buff), "[<0x%x>] %s + 0x%x/0x%x\n", 
			trace->rip, trace->symbol_name, trace->offset, trace->size);
	printf("%s", buff);
}

int search_symbol_by_addr(uint64_t rip, CALL_TRACE *trace)
{
	int i;

	for (i = 0; i < symtab_num; i++) {
		if (symtab_ptr[i].st_value == (unsigned int)rip) {
			trace->symbol_name = strtab_buffer + symtab_ptr[i].st_name;
			trace->symbol_addr = rip;
			trace->size = symtab_ptr[i].st_size;
			return 0;
		}
	}

	return -1;
}

void print_symtab(void)
{
	int i;

        for (i = 0; i < symtab_num; i++) {
                fprintf(stdout,"%4d     %25s    0x%08x  x%08x   0x%02x  %4d\n", i,
                        strtab_buffer + symtab_ptr[i].st_name,
                        symtab_ptr[i].st_value,
                        symtab_ptr[i].st_size,
                        symtab_ptr[i].st_info,
                        symtab_ptr[i].st_shndx);
        }
}

int load_elf_symbols(char *elf_file)
{
	unsigned int strtab_off, strtab_size;
	int phdr_len, shdr_len;
	int shstrtab_off, shstrtab_len;
	int symtab_off, symtab_size, i;
	char *buffer;

	assert(elf_file != NULL);
	elf_fd = open(elf_file, O_RDONLY);
	if (elf_fd == -1) {
		perror("open");
		goto out;
	}

	if (fstat(elf_fd, &elf_stat) == -1) {
		perror("fstat");
		goto out;
	}

	elf_ehdr = mmap(0, elf_stat.st_size, PROT_READ, MAP_SHARED, elf_fd, 0);
	if (elf_ehdr == MAP_FAILED) {
		perror("mmap");
		goto out;
	}

/*
	if (check_elf_header(elf_ehdr) == -1) {
		printf("check elf failed.\n");
		goto out_mmap;
	}
*/

#ifdef X86_32
	elf_phdr = (Elf32_Phdr *)((uint64_t)elf_ehdr + elf_ehdr->e_phoff);
	elf_shdr = (Elf32_Shdr *)((uint64_t)elf_ehdr + elf_ehdr->e_shoff);
#else
	elf_phdr = (Elf64_Phdr *)((uint64_t)elf_ehdr + elf_ehdr->e_phoff);
	elf_shdr = (Elf64_Shdr *)((uint64_t)elf_ehdr + elf_ehdr->e_shoff);
#endif

	shstrtab = &elf_shdr[elf_ehdr->e_shstrndx];
	shstrtab_off = (unsigned int)shstrtab->sh_offset;
	shstrtab_len = shstrtab->sh_size;
	real_strtab = (char *)((uint64_t)elf_ehdr + shstrtab_off);

	buffer = malloc(shstrtab_len + 1);
	if (!buffer) {
		printf("Malloc faled.\n");
		goto out;
	}

	memcpy(buffer, real_strtab, shstrtab_len + 1);
	shdr_len = elf_ehdr->e_shoff;

	for (i = 0 ; i < (int)elf_ehdr->e_shnum ; i++){
		if (!strcmp(buffer + elf_shdr[i].sh_name,".symtab")) {
			symtab_off = (unsigned int)elf_shdr[i].sh_offset;
			symtab_size = (unsigned int)elf_shdr[i].sh_size;
			symtab_num = (int )(elf_shdr[i].sh_size / elf_shdr[i].sh_entsize);
                }

                if (!strcmp(buffer + elf_shdr[i].sh_name,".strtab")) {
			strtab_off = (unsigned int)elf_shdr[i].sh_offset;
			strtab_size = (unsigned int)elf_shdr[i].sh_size;
		}
        }
	free(buffer);

	strtab_ptr = (char *)((uint64_t)elf_ehdr + strtab_off);
	strtab_buffer = malloc(strtab_size + 1);
	if (!strtab_buffer) {
		printf("Malloc failed.\n");
		goto out;
	}

	memcpy(strtab_buffer, strtab_ptr, strtab_size + 1);

	symtab_ptr = malloc(symtab_size + 1);
	if (!symtab_ptr) {
		printf("Malloc failed.\n");
		free(strtab_ptr);
		goto out;
	}
	memcpy(symtab_ptr, (char *)((uint64_t)elf_ehdr + symtab_off), symtab_size + 1);

	return 0;

out_mmap:
	munmap(elf_ehdr, elf_stat.st_size);
out:
	close(elf_fd);
	return -1;
}

void free_elf_mmap(void)
{
	munmap(elf_ehdr, elf_stat.st_size);
	close(elf_fd);
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
	sa.sa_sigaction = signal_handler;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGSEGV, &sa, NULL) == -1) {
		perror("sigaction");
		return -1;
	}

	return 0;
}

int calltrace_init(void)
{
	char self_path[1024];

	if (signal_init() == -1)
		return -1;

	get_self_path(self_path, sizeof(self_path));
	if (self_path[0] == '\0')
		return -1;

	if (load_elf_symbols(self_path) == -1)
		return -1;

	/* We just want to use the strtab_ptr & symtab_str that has allocated 
	 * above, so we can munmap the file now.
	 */ 
	free_elf_mmap();
	print_symtab();

	return 0; 
}

void calltrace_exit(void)
{
	free(strtab_buffer);
	free(symtab_ptr);
}
