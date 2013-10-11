/*
 * libelf.c (c) 2013	wzt http://www.cloud-sec.org
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "libelf.h"

static void *elf_mem = NULL;
static int elf_fd;
static struct stat elf_stat;

static Elf64_Ehdr *elf_hdr = NULL;
static Elf64_Shdr *elf_shstr_hdr = NULL;
static Elf64_Shdr *elf_str_hdr = NULL;
static char *elf_shstr_table = NULL;
static char *elf_str_table = NULL;
static Elf64_Sym *elf_symtab = NULL;
static int elf_symtab_num = 0;

int elf_init(const char *binary_path)
{
	if ((elf_fd = open(binary_path, O_RDONLY)) == -1) {
		perror("open");
		goto out;
	}

	if (stat(binary_path, &elf_stat) == -1) {
		perror("stat");
		goto out;
	}

	elf_mem = mmap(NULL, elf_stat.st_size, PROT_READ, MAP_PRIVATE, elf_fd, 0);
	if (elf_mem == MAP_FAILED) {
		perror("mmap");
		goto out;
	}
	return 0;

out:
	close(elf_fd);
	return -1;
}

void elf_exit(void)
{
	munmap(elf_mem, elf_stat.st_size);
	close(elf_fd);
}

void print_elf_hdr_ident(Elf64_Ehdr *elf_hdr)
{
	int i;

	printf("Elf header:\n");
	printf("\tMagic:");
	for (i = 0; i < EI_NIDENT; i++)
		printf("0x%02x ", elf_hdr->e_ident[i]);
	printf("\n");
}

int print_elf_hdr_class(Elf64_Ehdr *elf_hdr)
{
	switch (elf_hdr->e_ident[EI_CLASS]) {
	case ELFCLASSNONE:
		printf("\tclass: Invalid class\n");
		break;
	case ELFCLASS32:
		printf("\tclass: 32-bit objects\n");
		break;
	case ELFCLASS64:
		printf("\tclass: 64-bit objects\n");
		break;
	case ELFCLASSNUM:
		break;
	default:
		return -1;
	}

	return 0;
}

int print_elf_hdr_endian(Elf64_Ehdr *elf_hdr)
{
	switch (elf_hdr->e_ident[EI_DATA]) {
	case ELFDATANONE:
		printf("\tendian: Invalid data encoding\n");
		break;
	case ELFDATA2LSB:
		printf("\tendian: little endian\n");
		break;
	case ELFDATA2MSB:
		printf("\tendian: big endian\n");
		break;
	case ELFDATANUM:
		break;
	default:
		return -1;
	}

	return 0;
}

void print_elf_hdr_version(Elf64_Ehdr *elf_hdr)
{
	printf("\tversion: %d\n", elf_hdr->e_ident[EI_VERSION]);
}

int print_elf_hdr_osabi(Elf64_Ehdr *elf_hdr)
{
	switch (elf_hdr->e_ident[EI_OSABI]) {
	case ELFOSABI_NONE:
		printf("\tosabi: UNIX System V ABI\n");
		break;
	case ELFOSABI_HPUX:
		printf("\tosabi: HP-UX\n");
		break;
	case ELFOSABI_NETBSD:
		printf("\tosabi: NetBSD\n");
		break;
	case ELFOSABI_LINUX:
		printf("\tosabi: Linux\n");
		break;
	case ELFOSABI_SOLARIS:
		printf("\tosabi: Sun Solaris\n");
		break;
	case ELFOSABI_AIX:
		printf("\tosabi: IBM AIX\n");
		break;
	case ELFOSABI_IRIX:
		printf("\tosabi: SGI Irix\n");
		break;
	case ELFOSABI_FREEBSD:
		printf("\tosabi: FreeBSD\n");
		break;
	case ELFOSABI_TRU64:
		printf("\tosabi: Compaq TRU64 UNIX\n");
		break;
	case ELFOSABI_MODESTO:
		printf("\tosabi: Novell Modesto\n");
		break;
	case ELFOSABI_OPENBSD:
		printf("\tosabi: OpenBSD\n");
		break;
	case ELFOSABI_ARM:
		printf("\tosabi: ARM\n");
		break;
	case ELFOSABI_STANDALONE:
		printf("\tosabi: Standalone (embedded) application\n");
		break;
	default:
		return -1;
	}

	return 0;
}

int print_elf_hdr_abiversion(Elf64_Ehdr *elf_hdr)
{
	printf("\tabiversion: %d\n", elf_hdr->e_ident[EI_ABIVERSION]);
}

int print_elf_hdr_object_type(Elf64_Ehdr *elf_hdr)
{
	switch (elf_hdr->e_type) {
	case ET_NONE:
		printf("\ttype: No file type\n");
		break;
	case ET_REL:
		printf("\ttype: Relocatable file\n");
		break;
	case ET_EXEC:
		printf("\ttype: Executable file\n");
		break;
	case ET_DYN:
		printf("\ttype: Shared object file\n");
		break;
	case ET_CORE:
		printf("\ttype: Core file\n");
		break;
	case ET_NUM:
		printf("\ttype: Number of defined types\n");
		break;
	case ET_LOOS:
		printf("\ttype: OS-specific range start\n");
		break;
	case ET_HIOS:
		printf("\ttype: OS-specific range end\n");
		break;
	case ET_LOPROC:
		printf("\ttype: Processor-specific range start\n");
		break;
	case ET_HIPROC:
		printf("\ttype: Processor-specific range end\n");
		break;
	default:
		return -1;
	}

	return 0;
}

int print_elf_hdr_machine(Elf64_Ehdr *elf_hdr)
{
	switch (elf_hdr->e_machine) {
	case EM_386:
		printf("\t:machine: Intel 80386\n");
		break;
	case EM_ARM:
		printf("\tmachine: ARM\n");
		break;
	case EM_X86_64:
		printf("\tmachine: AMD x86-64 architecture\n");
		break;
	default:
		printf("\tmachine: unkown machine %d\n", 
			elf_hdr->e_machine);
		return -1;
	}

	return 0;
}

int print_elf_hdr_elf_version(Elf64_Ehdr *elf_hdr)
{
	switch (elf_hdr->e_version) {
	case EV_NONE:
		printf("\tversion: Invalid ELF version\n");
		break;
	case EV_CURRENT:
		printf("\tversion: Current version(0x%02x)\n", 
			elf_hdr->e_version);
		break;
	case EV_NUM:
		break;
	default:
		return -1;
	}
	
	return 0;
}

int print_elf_hdr_entry(Elf64_Ehdr *elf_hdr)
{
	printf("\tentry: 0x%016x\n", elf_hdr->e_entry);

	return 0;
}

int print_elf_hdr_phoff(Elf64_Ehdr *elf_hdr)
{
	printf("\tProgram header table file offset: 0x%016x\n", elf_hdr->e_phoff);

	return 0;
}

int print_elf_hdr_shoff(Elf64_Ehdr *elf_hdr)
{
	printf("\tSection header table file offset: 0x%016x\n", elf_hdr->e_shoff);

	return 0;
}

int print_elf_hdr_flags(Elf64_Ehdr *elf_hdr)
{
	printf("\tProcessor-specific flags: %d\n", elf_hdr->e_flags);

	return 0;
}

int print_elf_hdr_size(Elf64_Ehdr *elf_hdr)
{
	printf("\tELF header size: %d\n", elf_hdr->e_ehsize);

	return 0;
}

int print_elf_hdr_phentsize(Elf64_Ehdr *elf_hdr)
{
	printf("\tProgram header table entry size: %d\n", elf_hdr->e_phentsize);

	return 0;
}

int print_elf_hdr_phnum(Elf64_Ehdr *elf_hdr)
{
	printf("\tProgram header table entry count: %d\n", elf_hdr->e_phnum);

	return 0;
}

int print_elf_hdr_shentsize(Elf64_Ehdr *elf_hdr)
{
	printf("\tSection header table entry size: %d\n", elf_hdr->e_shentsize);

	return 0;
}

int print_elf_hdr_shnum(Elf64_Ehdr *elf_hdr)
{
	printf("\tSection header table entry count: %d\n", elf_hdr->e_shnum);

	return 0;
}

int print_elf_hdr_shstrndx(Elf64_Ehdr *elf_hdr)
{
	printf("\tSection header string table index: %d\n", elf_hdr->e_shstrndx);

	return 0;
}

int check_elf_header(Elf64_Ehdr *elf_hdr)
{
	if ((elf_hdr->e_ident[EI_MAG0] == ELFMAG0)
		&& (elf_hdr->e_ident[EI_MAG1] == ELFMAG1)
		&& (elf_hdr->e_ident[EI_MAG2] == ELFMAG2)) {
		return 0;
	}

	return -1;
}

int parse_elf_header(const char *binary_path)
{
	if (elf_init(binary_path) == -1)
		return -1;
	
	elf_hdr = (Elf64_Ehdr *)elf_mem;
	
	if (check_elf_header(elf_hdr) == -1)
		return -1;

	print_elf_hdr_ident(elf_hdr);
	if (print_elf_hdr_class(elf_hdr) == -1)
		return -1;

	if (print_elf_hdr_endian(elf_hdr) == -1)
		return -1;

	print_elf_hdr_version(elf_hdr);
	if (print_elf_hdr_osabi(elf_hdr) == -1)
		return -1;

	print_elf_hdr_abiversion(elf_hdr);
	if (print_elf_hdr_object_type(elf_hdr) == -1)
		return -1;

	if (print_elf_hdr_machine(elf_hdr) == -1)
		return -1;

	if (print_elf_hdr_elf_version(elf_hdr) == -1)
		return -1;

	if (print_elf_hdr_entry(elf_hdr) == -1)
		return -1;

	if (print_elf_hdr_phoff(elf_hdr) == -1)
		return -1;

	if (print_elf_hdr_shoff(elf_hdr) == -1)
		return -1;

	if (print_elf_hdr_flags(elf_hdr) == -1)
		return -1;

	if (print_elf_hdr_size(elf_hdr) == -1)
		return -1;

	if (print_elf_hdr_phentsize(elf_hdr) == -1)
		return -1;

	if (print_elf_hdr_phnum(elf_hdr) == -1)
		return -1;

	if (print_elf_hdr_shentsize(elf_hdr) == -1)
		return -1;

	if (print_elf_hdr_shnum(elf_hdr) == -1)
		return -1;

	if (print_elf_hdr_shstrndx(elf_hdr) == -1)
		return -1;

	elf_exit();
}

int parse_elf_section_name(Elf64_Ehdr *elf_hdr)
{
	Elf64_Shdr *elf_shdr = NULL;

	elf_shdr = (Elf64_Shdr *)(elf_mem + elf_hdr->e_shoff);
	elf_shstr_hdr = (Elf64_Shdr *)(elf_shdr + elf_hdr->e_shstrndx);
	elf_shstr_table = (void *)(elf_mem + elf_shstr_hdr->sh_offset);

	return 0;
}

int parse_elf_string_table(Elf64_Ehdr *elf_hdr)
{
	Elf64_Shdr *elf_shdr = NULL;
	int i;

	elf_shdr = (Elf64_Shdr *)(elf_mem + elf_hdr->e_shoff);
	for (i = 1; i < elf_hdr->e_shnum; i++) {
		if (!strcmp(elf_shstr_table + elf_shdr[i].sh_name, ".strtab")) {
			elf_str_table = (char *)((uint64_t)elf_mem + elf_shdr[i].sh_offset);
			return 0;
		}
	}

	return -1;
}

void print_symtab(void)
{
	int i;

	printf("idx\tname\t\t\taddr\t\tsize\n");
	for (i = 0; i < elf_symtab_num; i++) {
		printf("%2d\t%-16s\t0x%016x\t0x%016x\n",
			i, elf_str_table + elf_symtab[i].st_name,
			elf_symtab[i].st_value, elf_symtab[i].st_size);
	}
}

int search_symbol_by_addr(unsigned long rip, CALL_TRACE *trace)
{
        int i;

        for (i = 0; i < elf_symtab_num; i++) {
                if (elf_symtab[i].st_value == (unsigned int)rip) {
                        trace->symbol_name = elf_str_table + elf_symtab[i].st_name;
                        trace->symbol_addr = rip;
                        trace->size = elf_symtab[i].st_size;
                        return 0;
                }
        }

        return -1;
}

int parse_elf_symbol_table(Elf64_Ehdr *elf_hdr)
{
	Elf64_Shdr *elf_shdr = NULL;
	int i;

	elf_shdr = (Elf64_Shdr *)(elf_mem + elf_hdr->e_shoff);
	for (i = 1; i < elf_hdr->e_shnum; i++) {
		if (!strcmp(elf_shstr_table + elf_shdr[i].sh_name, ".symtab")) {
			//printf("found .symtab\n");
			elf_symtab = (Elf64_Sym *)(elf_mem + elf_shdr[i].sh_offset);
			elf_symtab_num = elf_shdr[i].sh_size / elf_shdr[i].sh_entsize;
			return 0;
		}
	}
	printf("not found .symtab\n");

	return -1;
}

int __parse_elf_section(Elf64_Ehdr *elf_hdr)
{
	Elf64_Shdr *elf_shdr = NULL;
	int i;

	elf_shdr = (Elf64_Shdr *)(elf_mem + elf_hdr->e_shoff);

	printf("idx\tsh_name\t\t\tsh_type\t\tsh_addr\t\t\tsh_offset\t\tsh_size\t\n");
	for (i = 1; i < elf_hdr->e_shnum; i++) {
		printf("%2d\t%-16s\t0x%08x\t0x%016x\t0x%016x\t0x%x\n",
			i, elf_shstr_table + elf_shdr[i].sh_name, 
			elf_shdr[i].sh_type,
			elf_shdr[i].sh_addr, elf_shdr[i].sh_offset,
			elf_shdr[i].sh_size);
	}
			
	return 0;
}

int parse_elf_section(const char *binary_path)
{
	if (elf_init(binary_path) == -1)
		return -1;
	
	elf_hdr = (Elf64_Ehdr *)elf_mem;
	
	if (check_elf_header(elf_hdr) == -1)
		return -1;

	if (parse_elf_section_name(elf_hdr) == -1)
		return -1;

	if (__parse_elf_section(elf_hdr) == -1)
		return -1;

	return 0;
}

int parse_elf_symbol(const char *binary_path)
{
	if (elf_init(binary_path) == -1)
		return -1;
	
	elf_hdr = (Elf64_Ehdr *)elf_mem;
	
	if (check_elf_header(elf_hdr) == -1)
		return -1;

	if (parse_elf_section_name(elf_hdr) == -1)
		return -1;

	if (parse_elf_string_table(elf_hdr) == -1)
		return -1;

	if (parse_elf_symbol_table(elf_hdr) == -1)
		return -1;

	return 0;
}
