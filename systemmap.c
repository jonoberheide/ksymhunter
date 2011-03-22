/*
 * systemmap.c
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
ksymhunter_systemmap(char *name)
{
	FILE *f;
	unsigned long addr;
	char dummy, sname[512];
	int ret, oldstyle = 0;
	struct utsname ver;

	uname(&ver);
	if (strncmp(ver.release, "2.6", 3)) {
		oldstyle = 1;
	}
	sprintf(sname, "/boot/System.map-%s", ver.release);
	f = fopen(sname, "r");
	if (!f) {
		sprintf(sname, "/boot/System.map-genkernel-%s-%s", ver.machine, ver.release);
		f = fopen(sname, "r");
		if (!f) {
			return 0;
		}
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
