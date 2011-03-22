#ifndef KSYMHUNTER_H
#define KSYMHUNTER_H

unsigned long ksymhunter_kallsyms(char *symbol);
unsigned long ksymhunter_systemmap(char *symbol);

#endif
