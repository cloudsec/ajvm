#ifndef LIBELF_H
#define LIBELF_H

#include <elf.h>
#include "trace.h"

int elf_init(const char *binary_path);
void elf_exit(void);
int check_elf_header(Elf64_Ehdr *elf_hdr);
int parse_elf_section_name(Elf64_Ehdr *elf_hdr);
int parse_elf_symbol_table(Elf64_Ehdr *elf_hdr);
int __parse_elf_section(Elf64_Ehdr *elf_hdr);
int parse_elf_section(const char *binary_path);
int parse_elf_symbol(const char *binary_path);
int search_symbol_by_addr(uint64_t rip, CALL_TRACE *trace);

#endif
