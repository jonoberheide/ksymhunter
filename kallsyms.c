/*
 * kallsyms.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

unsigned long
ksymhunter_kallsyms(char *name)
{
	FILE *f;
	unsigned long addr;
	char dummy, sname[512];
	int ret, oldstyle = 0;

	f = fopen("/proc/kallsyms", "r");
	if (!f) {
		f = fopen("/proc/ksyms", "r");
		if (!f) {
			return 0;
		}
		oldstyle = 1;
	}

	ret = 0;
	while(ret != EOF) {
		if (!oldstyle) {
			ret = fscanf(f, "%p %c %s\n", (void **)&addr, &dummy, sname);
		} else {
			ret = fscanf(f, "%p %s\n", (void **)&addr, sname);
			if (ret == 2) {
				char *p;
				if (strstr(sname, "_O/") || strstr(sname, "_S.")) {
					continue;
				}
				p = strrchr(sname, '_');
				if (p > ((char *)sname + 5) && !strncmp(p - 3, "smp", 3)) {
					p = p - 4;
					while (p > (char *)sname && *(p - 1) == '_') {
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
