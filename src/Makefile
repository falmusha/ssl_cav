CC=cc
CFLAGS=-g -Wall -Wmissing-prototypes -Wno-missing-field-initializers
LDFLAGS=
LIBRARIES += -lcrypto -lssl
SOURCES=handshake.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=sslcav

all: $(OBJECTS)
		$(CC) $(CFLAGS) $(LDFLAGS) -o $(EXECUTABLE) $(OBJECTS) $(LIBRARIES)

clean:
		rm $(EXECUTABLE) $(OBJECTS)
