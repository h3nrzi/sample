CC=gcc
CFLAGS=-std=c99 -Wall -Wextra -pedantic -O2

all: firewall

firewall: main.o
	$(CC) $(CFLAGS) -o firewall main.o

main.o: main.c
	$(CC) $(CFLAGS) -c main.c

clean:
	rm -f firewall main.o

.PHONY: all clean
