/*
 * ksymhunter.c
 *
 * Jon Oberheide <jon@oberheide.org>
 * http://jon.oberheide.org
 *
 * Routines for hunting down kernel symbols from from kallsyms,
 * System.map, vmlinux, vmlinuz, and remote symbol servers.
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
#include <netdb.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

unsigned long try_sysmap(char *name, char *path);
unsigned long try_vmlinux(char *name, char *path);
unsigned long try_vmlinuz(char *name, char *path);
unsigned long try_remote(char *name, char *path);

#define SOURCE(FP, FMT, ARGS) { .fp = FP, .fmt = FMT, .args = ARGS }

#define SYSMAP(FMT, ARGS)  SOURCE(try_sysmap, FMT, ARGS)
#define SYSMAP_0(FMT)      SYSMAP(FMT, 0)
#define SYSMAP_1(FMT)      SYSMAP(FMT, 1)
#define SYSMAP_2(FMT)      SYSMAP(FMT, 2)

#define VMLINUX(FMT, ARGS) SOURCE(try_vmlinux, FMT, ARGS)
#define VMLINUX_0(FMT)     VMLINUX(FMT, 0)
#define VMLINUX_1(FMT)     VMLINUX(FMT, 1)
#define VMLINUX_2(FMT)     VMLINUX(FMT, 2)

#define VMLINUZ(FMT, ARGS) SOURCE(try_vmlinuz, FMT, ARGS)
#define VMLINUZ_0(FMT)     VMLINUZ(FMT, 0)
#define VMLINUZ_1(FMT)     VMLINUZ(FMT, 1)
#define VMLINUZ_2(FMT)     VMLINUZ(FMT, 2)

#define REMOTE(FMT, ARGS)  SOURCE(try_remote, FMT, ARGS)
#define REMOTE_0(FMT)      REMOTE(FMT, 0)

#define REMOTE_HOST "kernelvulns.org"
#define REMOTE_PORT "80"

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
	VMLINUZ_1("/boot/vmlinuz-%s"),
	VMLINUZ_2("/boot/kernel-genkernel-%s-%s"),
	VMLINUZ_1("/vmlinuz-%s"),
	VMLINUZ_2("/kernel-genkernel-%s-%s"),
	VMLINUZ_1("/usr/src/linux-%s/arch/x86/boot/bzImage"),
	VMLINUZ_0("/boot/vmlinuz"),
	VMLINUZ_0("/vmlinuz"),
	VMLINUZ_0("/usr/src/linux/arch/x86/boot/bzImage"),
	REMOTE_0(REMOTE_HOST),
};

unsigned long
try_sysmap(char *name, char *path)
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
try_vmlinux(char *name, char *path)
{
	char cmd[512];
	char *tmpfile = ".sysmap";
	unsigned long addr;
	
	snprintf(cmd, sizeof(cmd), "nm %s &> %s", path, tmpfile);
	system(cmd);
	addr = try_sysmap(name, tmpfile);
	unlink(tmpfile);

	return addr;
}

unsigned long
try_vmlinuz(char *name, char *path)
{
	FILE *fp;
	void *mem;
	char *token, cmd[1024], out[1024];
	unsigned long *ptr, rodata, curr = 0, prev = 0;
	int i, fd, ret, ctr, off, num_syms;
	struct stat sb;

	unsigned long kallsyms_num_syms;
	unsigned long *kallsyms_addresses;
	unsigned long *kallsyms_markers;
	uint8_t *kallsyms_names;
	uint8_t *kallsyms_token_table;
	uint16_t *kallsyms_token_index;

	char *tmpfile = ".vmlinuz";
	char *madness_1 = "for pos in `tr \"\037\213\010\nxy\" \"\nxy=\" < \"%s\" | grep -abo \"^xy\"`; do pos=${pos%%:*}; tail -c+$pos \"%s\" | gunzip > %s 2> /dev/null; break; done";
	char *madness_2 = "readelf -S %s | grep \"\\.rodata\" | awk '{print $6}'";

	ret = stat(path, &sb);
	if (ret == -1) {
		return 0;
	}

	snprintf(cmd, sizeof(cmd), madness_1, path, path, tmpfile);
	system(cmd);

	ret = stat(tmpfile, &sb);
	if (ret == -1) {
		return 0;
	}

	snprintf(cmd, sizeof(cmd), madness_2, tmpfile);

	fp = popen(cmd, "r");
	if (!fp) {
		return 0;
	}
	fgets(out, sizeof(out), fp);
	pclose(fp);

	rodata = strtoul(out, NULL, 16);

	fd = open(tmpfile, O_RDONLY);
	if (fd == -1) {
		return 0;
	}

	ret = fstat(fd, &sb);
	if (ret == -1) {
		return 0;
	}

	mem = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		return 0;
	}

	ptr = mem + rodata;

	for (ctr = 0; ctr < 5000; ++ctr, ++ptr) {
		prev = curr;
		curr = *ptr;
		if (prev > curr) {
			ctr = 0;
		}
	}

	for (; prev <= curr; ++ptr) {
		prev = curr;
		curr = *ptr;
	}

	num_syms = curr;
	kallsyms_num_syms = (unsigned long) (ptr - 1);
	kallsyms_addresses = (unsigned long *) (kallsyms_num_syms - (num_syms * sizeof(unsigned long)));
	kallsyms_names = (uint8_t *) (kallsyms_num_syms + (1 * sizeof(unsigned long)));

	for (ptr = (unsigned long *) kallsyms_names; *ptr != 0; ++ptr) { }

	kallsyms_markers = ptr;
	kallsyms_token_table = (uint8_t *) (kallsyms_markers + (((num_syms + 255) / 256)));
	token = (char *) kallsyms_token_table;

	for (i = 0; i < 256; ++i) {
		token += strlen(token) + 1;
	}

	kallsyms_token_index = (uint16_t *) ((unsigned long) (token + sizeof(unsigned long)) & ~(sizeof(unsigned long) - 1));

	for (i = 0, off = 0; i < kallsyms_num_syms; i++) {
		char buf[128];
		char *result = buf;
		int len, skipped_first = 0;
		uint8_t *tptr, *data;

		data = &kallsyms_names[off];
		len = *data;
		data++;
		off += len + 1;

		while (len) {
			tptr = &kallsyms_token_table[kallsyms_token_index[*data]];
			data++;
			len--;
			while (*tptr) {
				if (skipped_first) {
					*result = *tptr;
					result++;
				} else {
					skipped_first = 1;
				}
				tptr++;
			}
		}
		*result = '\0';

		if (strcmp(buf, name) == 0) {
			return kallsyms_addresses[i];
		}
	}

	close(fd);
	munmap(mem, sb.st_size);
	unlink(tmpfile);

	return 0;
}

unsigned long
try_remote(char *name, char *path)
{
	int ret, sock;
	struct addrinfo *result;
	struct addrinfo hints;
	unsigned long addr;
	struct utsname ver;
	char msg[512];

	uname(&ver);

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;

	ret = getaddrinfo(REMOTE_HOST, REMOTE_PORT, &hints, &result);
	if (ret != 0) {
		return 0;
	}

 	sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (sock == -1) {
		return 0;
	}

	ret = connect(sock, result->ai_addr, result->ai_addrlen);
	if (ret == -1) {
		close(sock);
		return 0;
	}

	snprintf(msg, sizeof(msg), "%s|%s|%s", ver.machine, ver.release, name);

	ret = send(sock, msg, strlen(msg), 0);
	if (ret != strlen(msg)) {
		close(sock);
		return 0;
	}

	ret = recv(sock, &addr, sizeof(addr), 0);
	if (ret != sizeof(addr)) {
		close(sock);
		return 0;
	}

	close(sock);
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
