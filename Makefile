
CC = gcc
LD = gcc
RM = rm -f
CFLAGS = -g -Wall
LDFLAGS = 

PROG = ksymhunter
OBJS = ksymhunter.o

all: $(PROG)

$(PROG): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(PROG)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) $(PROG) $(OBJS)
