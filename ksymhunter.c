/*
 * ksymhunter.c
 *
 * Jon Oberheide <jon@oberheide.org>
 * http://jon.oberheide.org
 *
 * Routines for extracting kernel symbols from kallsyms, System.map,
 * vmlinux, and other sources.
 *
 * System.map parsing adapted from spender's enlightenment.
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

unsigned long parse_sysmap(char *name, char *path);
unsigned long parse_vmlinux(char *name, char *path);

#define SOURCE(FP, FMT, ARGS) { .fp = FP, .fmt = FMT, .args = ARGS }

#define SYSMAP(FMT, ARGS)  SOURCE(parse_sysmap, FMT, ARGS)
#define SYSMAP_0(FMT)      SYSMAP(FMT, 0)
#define SYSMAP_1(FMT)      SYSMAP(FMT, 1)
#define SYSMAP_2(FMT)      SYSMAP(FMT, 2)

#define VMLINUX(FMT, ARGS) SOURCE(parse_vmlinux, FMT, ARGS)
#define VMLINUX_0(FMT)     VMLINUX(FMT, 0)
#define VMLINUX_1(FMT)     VMLINUX(FMT, 1)
#define VMLINUX_2(FMT)     VMLINUX(FMT, 2)

struct source {
	int args;
	char *fmt;
	unsigned long (*fp) (char *, char *);
};

struct source sources[] = {
	SYSMAP_0("/proc/kallsyms"),
	SYSMAP_0("/proc/ksyms"),
	SYSMAP_1("/boot/System.map-%s"),
	SYSMAP_2("/boot/System.map-genkernel-%s-%s"),
	SYSMAP_1("/System.map-%s"),
	SYSMAP_2("/System.map-genkernel-%s-%s"),
	SYSMAP_1("/usr/src/linux-%s/System.map"),
	SYSMAP_1("/lib/modules/%s/System.map"),
	SYSMAP_0("/boot/System.map"),
	SYSMAP_0("/System.map"),
	SYSMAP_0("/usr/src/linux/System.map"),
	VMLINUX_1("/boot/vmlinux-%s"),
	VMLINUX_1("/boot/vmlinux-%s.debug"),
	VMLINUX_1("/boot/.debug/vmlinux-%s"),
	VMLINUX_1("/boot/.debug/vmlinux-%s.debug"),
	VMLINUX_1("/lib/modules/%s/vmlinux"),
	VMLINUX_1("/lib/modules/%s/vmlinux.debug"),
	VMLINUX_1("/lib/modules/%s/.debug/vmlinux"),
	VMLINUX_1("/lib/modules/%s/.debug/vmlinux.debug"),
	VMLINUX_1("/usr/lib/debug/lib/modules/%s/vmlinux"),
	VMLINUX_1("/usr/lib/debug/lib/modules/%s/vmlinux.debug"),
	VMLINUX_1("/usr/lib/debug/boot/vmlinux-%s"),
	VMLINUX_1("/usr/lib/debug/boot/vmlinux-%s.debug"),
	VMLINUX_1("/usr/lib/debug/vmlinux-%s"),
	VMLINUX_1("/usr/lib/debug/vmlinux-%s.debug"),
	VMLINUX_1("/var/cache/abrt-di/usr/lib/debug/lib/modules/%s/vmlinux"),
	VMLINUX_1("/var/cache/abrt-di/usr/lib/debug/lib/modules/%s/vmlinux.debug"),
	VMLINUX_1("/var/cache/abrt-di/usr/lib/debug/boot/vmlinux-%s"),
	VMLINUX_1("/var/cache/abrt-di/usr/lib/debug/boot/vmlinux-%s.debug"),
	VMLINUX_1("/usr/src/linux-%s/vmlinux"),
	VMLINUX_0("/usr/src/linux/vmlinux"),
	VMLINUX_0("/boot/vmlinux"),
	VMLINUX_0("/vmlinux"),
};

unsigned long
parse_sysmap(char *name, char *path)
{
	FILE *f;
	unsigned long addr;
	char dummy, sname[512];
	int ret = 0, oldstyle = 0;
	struct utsname ver;

	f = fopen(path, "r");
	if (!f) {
		return 0;
	}

	uname(&ver);
	if (strncmp(ver.release, "2.6", 3)) {
		oldstyle = 1;
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
parse_vmlinux(char *name, char *path)
{
	char cmd[512];
	char *tmpfile = ".sysmap";
	unsigned long addr;
	
	snprintf(cmd, sizeof(cmd), "nm %s &> %s", path, tmpfile);
	system(cmd);
	addr = parse_sysmap(name, tmpfile);
	unlink(tmpfile);

	return addr;
}

unsigned long
ksymhunter(char *name)
{
	char path[512];
	struct source *source;
	struct utsname ver;
	unsigned long addr;
	int i, count;

	uname(&ver);

	count = sizeof(sources) / sizeof(struct source);
	for (i = 0; i < count; ++i) {
		source = &sources[i];

		if (source->args == 0) {
			snprintf(path, sizeof(path), source->fmt, "");
		} else if (source->args == 1) {
			snprintf(path, sizeof(path), source->fmt, ver.release);
		} else if (source->args == 2) {
			snprintf(path, sizeof(path), source->fmt, ver.machine, ver.release);
		}

		addr = source->fp(name, path);
		if (addr) {
			printf("[+] resolved %s using %s\n", name, path);
			return addr;
		}
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

	addr = ksymhunter(symbol);
	if (!addr) {
		printf("[-] failed to resolve %s\n", symbol);
		exit(1);
	}

	printf("[+] resolved %s to 0x%lx\n", symbol, addr);

	return 0;
}
