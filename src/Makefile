CC=gcc
CFLAGS=-g -Wall -Wmissing-prototypes -Wno-missing-field-initializers
LDFLAGS=
LIBRARIES += -lcrypto -lssl
SOURCES=handshake.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=sslcav

all: $(OBJECTS) cav
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(EXECUTABLE) $(OBJECTS) $(LIBRARIES)

cav: 
	$(CC) $(CFLAGS) $(LDFLAGS) -fPIC -shared -o cav.so cav.c

clean:
	rm $(EXECUTABLE) $(OBJECTS) cav.so
