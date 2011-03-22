/*
 * kallsyms.c
 *
 * Routines for parsing kallsyms/ksyms symbol tables.
 *
 * Adapted from spender's enlightenment.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

unsigned long
parse_kallsyms(char *name, char *path, int oldstyle)
{
	FILE *f;
	unsigned long addr;
	char dummy, sname[512];
	int ret = 0;

	f = fopen(path, "r");
	if (!f) {
		return 0;
	}

	while (ret != EOF) {
		if (!oldstyle) {
			ret = fscanf(f, "%p %c %s\n", (void **) &addr, &dummy, sname);
		} else {
			ret = fscanf(f, "%p %s\n", (void **) &addr, sname);
			if (ret == 2) {
				char *p;
				if (strstr(sname, "_O/") || strstr(sname, "_S.")) {
					continue;
				}
				p = strrchr(sname, '_');
				if (p > ((char *) sname + 5) && !strncmp(p - 3, "smp", 3)) {
					p = p - 4;
					while (p > (char *) sname && *(p - 1) == '_') {
						p--;
					}
					*p = '\0';
				}
			}
		}
		if (ret == 0) {
			fscanf(f, "%s\n", sname);
			continue;
		}
		if (!strcmp(name, sname)) {
			fclose(f);
			return addr;
		}
	}

	fclose(f);
	return 0;
}

unsigned long
ksymhunter_kallsyms(char *name)
{
	unsigned long addr;

	addr = parse_kallsyms(name, "/proc/kallsyms", 0);
	if (addr) {
		return addr;
	}

	addr = parse_kallsyms(name, "/proc/ksyms", 1);
	if (addr) {
		return addr;
	}

	return 0;
}
