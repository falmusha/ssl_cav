CC = gcc
CFLAGS = -g -w -c -fpic -std=c99
LIBRARIES = -lcrypto -lssl
SOURCES=cav.c verify.c util.c
OBJECTS=$(SOURCES:.c=.o)

all: handshake libcav

%.o: %.c
	$(CC) -o $@ $< $(CFLAGS) $(LIBRARIES) -I.

libcav: $(OBJECTS)
	$(CC) -shared -o libcav.so $(OBJECTS)

handshake:
	$(CC) -std=c99 -o handshake handshake.c -I. $(LIBRARIES)

clean:
	rm -f *.o *.so handshake

