CC=cc
CFLAGS=-g -Wall -Wmissing-prototypes -Wno-missing-field-initializers
LDFLAGS=
LIBRARIES += -lcrypto -lssl
SOURCES=secure_ssl.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=sslcav

all: $(OBJECTS)
		$(CC) $(CFLAGS) $(LDFLAGS) -o $(EXECUTABLE) $(OBJECTS) $(LIBRARIES)

clean:
		rm $(EXECUTABLE) $(OBJECTS)
