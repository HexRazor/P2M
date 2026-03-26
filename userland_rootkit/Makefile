CC = gcc
CFLAGS = -Wall -fPIC -D_GNU_SOURCE
LDFLAGS = -shared -ldl
TARGET = libsystemd-auth.so
SRCS = main.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c rootkit.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
