/*
 * ksymhunter.c
 *
 * Jon Oberheide <jon@oberheide.org>
 * http://jon.oberheide.org
 *
 * Helper routines to hunt down kernel symbols.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "ksymhunter.h"

unsigned long
ksymhunter(char *symbol)
{
	unsigned long addr;

	addr = ksymhunter_kallsyms(symbol);
	if (addr) {
		return addr;
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	char *symbol;
	unsigned long addr;

	if (argc < 2) {
		printf("usage: %s symbol_name\n", argv[0]);
		exit(1);
	}

	symbol = argv[1];

	printf("[+] trying to resolve %s...\n", symbol);

	addr = ksymhunter(argv[1]);
	if (!addr) {
		printf("[-] failed to resolve %s\n", symbol);
		exit(1);
	}

	printf("[+] resolved %s to 0x%lx\n", symbol, addr);

	return 0;
}
