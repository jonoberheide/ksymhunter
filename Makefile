
CC = gcc
LD = gcc
RM = rm -f
CFLAGS = -g -Wall

PROG = ksymhunter
OBJS = ksymhunter.o kallsyms.o systemmap.o

all: $(PROG)

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) $(PROG) $(OBJS)
