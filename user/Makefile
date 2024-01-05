CC = gcc
CFLAGS = -Wall -Wextra -Werror -pedantic -std=c99

fwsummary: fwsummary.c
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean
clean:
	rm -f fwsummary
