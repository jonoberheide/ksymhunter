/*
 * systemmap.c
 *
 * Routines for parsing System.map symbol tables.
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
#include <sys/types.h>
#include <sys/utsname.h>

unsigned long
parse_systemmap(char *name, char *path, int oldstyle)
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
ksymhunter_systemmap(char *name)
{
	int oldstyle;
	char path[512];
	struct utsname ver;
	unsigned long addr;

	uname(&ver);
	if (strncmp(ver.release, "2.6", 3)) {
		oldstyle = 1;
	}

	snprintf(path, sizeof(path), "/boot/System.map-%s", ver.release);
	addr = parse_systemmap(name, path, oldstyle);
	if (addr) {
		return addr;
	}

	snprintf(path, sizeof(path), "/boot/System.map-genkernel-%s-%s", ver.machine, ver.release);
	addr = parse_systemmap(name, path, oldstyle);
	if (addr) {
		return addr;
	}

	return 0;
}
