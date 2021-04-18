#

CC=gcc

SRC=stealthScan.c
SRC+=tcppkt03.c
SRC+=resolve.c

BIN=stealthScan

CFLAGS=-g


$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $(BIN) $(SRC)

clean:
	rm -f $(BIN) *.o
