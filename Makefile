CC := gcc
CFLAGS := -g -Wall -Werror

SRC = netmap.c
OBJ = ${SRC:.c=.o}

netmap: ${OBJ}
	@echo CC -o $@
	@$(CC) -o $@ ${OBJ}

clean:
	@rm -f netmap ${OBJ}
