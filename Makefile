
ksymhunter: ksymhunter.o kallsyms.o systemmap.o
	gcc ksymhunter.o kallsyms.o systemmap.o -o ksymhunter

ksymhunter.o: ksymhunter.c
	gcc -c ksymhunter.c

kallsyms.o: kallsyms.c
	gcc -c kallsyms.c

systemmap.o: systemmap.c
	gcc -c systemmap.c

clean:
	rm -f *.o ksymhunter
