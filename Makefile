NAME		= kite
CC		= clang
CARGS		= -Wall -Wextra -Wno-unused-result -Wno-strict-aliasing -Wno-unused-parameter
DBGARGS		= -g -DDEBUG
RLSARGS		= -O1
LDARGS		= -lpthread -ldl -rdynamic
CMDLINE		= -u kite0 -a 2001:420:44ff:fe::ff -d 2001:420:44ff:ff::148
FILES 		= main.c util.c fib.c
INC 		= kite.h

DBGOBJ     	= $(FILES:.c=.debug.o)
RLSOBJ     	= $(FILES:.c=.release.o)
BUILD		:= $(shell git rev-parse --short HEAD)

%.debug.o: %.c $(INC) Makefile
	@printf " C  DBG $(<)\n"
	@$(CC) $(CARGS) $(DBGARGS) -DBUILD=\"$(BUILD)\" -c $< -o $@

%.release.o: %.c $(INC) Makefile
	@printf " C  RLS $(<)\n"
	@$(CC) $(CARGS) $(RLSARGS) -DBUILD=\"$(BUILD)\" -c $< -o $@


all: $(DBGOBJ) $(RLSOBJ)
	@printf " LD DBG $(NAME).debug\n"
	@$(CC) $(CARGS) -o $(NAME).debug $(DBGOBJ) $(LDARGS)
	@printf " LD DBG $(NAME).release\n"
	@$(CC) $(CARGS) -o $(NAME).release $(RLSOBJ) $(LDARGS)

run-release: all 
	sudo ./kite.release $(CMDLINE)

run-debug: all 
	sudo ./kite.debug $(CMDLINE)

clean:
	rm -f $(NAME).release $(NAME).debug $(DBGOBJ) $(RLSOBJ)
