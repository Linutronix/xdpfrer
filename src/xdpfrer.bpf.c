#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

#undef bpf_printk
#define bpf_printk(fmt, ...)                            \
({                                                      \
        static const char ____fmt[] = fmt;              \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
    __uint(max_entries, 8);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct bpf_devmap_val));
} redirect_map SEC(".maps");;

SEC("xdp")
int prog(struct xdp_md *pkt)
{
    bpf_printk("before redirect");

    return bpf_redirect_map(&redirect_map, 0, BPF_F_BROADCAST);
}

SEC("xdp/devmap")
int prog_after_redirect(struct xdp_md *pkt)
{
    bpf_printk("redirected");

    return XDP_PASS;
}

