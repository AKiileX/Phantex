// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Phantex — DNS Resolution Probe (Lite / Fallback)
//
// Lightweight version of the DNS probe for kernels where the full
// dns.bpf.c exceeds the BPF verifier instruction limit (typically
// older 5.x kernels with the 4096-instruction cap).
//
// Differences from dns.bpf.c:
//   - No in-kernel DNS name parsing (raw wire bytes → userspace)
//   - No CO-RE iov_iter field branching (uses __iov only, kernel ≥ 5.8)
//   - Drastically fewer instructions → passes verifier on all 5.8+ kernels
//
// The Go reader detects raw wire-format names (starting with a length
// byte instead of an ASCII character) and parses them in userspace.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../include/events.h"
#include "../include/maps.h"

#define DNS_HEADER_LEN  12
#define DNS_PORT        53

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kprobe__udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!should_track_pid(pid))
        return 0;

    __u16 dst_port = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (dst_port != DNS_PORT)
        return 0;

    __u32 dst_addr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

    /* Read first iovec — simplified, no CO-RE branching */
    struct iov_iter *iter = &msg->msg_iter;
    const struct iovec *iov = NULL;
    bpf_probe_read_kernel(&iov, sizeof(iov), &iter->__iov);
    if (!iov)
        return 0;

    struct iovec first_iov;
    bpf_probe_read_kernel(&first_iov, sizeof(first_iov), iov);

    void *base = first_iov.iov_base;
    __u64 iov_len = first_iov.iov_len;

    if (!base || iov_len < DNS_HEADER_LEN + 1)
        return 0;

    /* Reserve ring buffer event */
    struct ph_dns_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    fill_header(&evt->hdr, EVENT_NETWORK_DNS);
    evt->dst_addr = dst_addr;
    evt->dst_port = DNS_PORT;
    evt->query_type = 0;

    /*
     * Copy raw DNS query bytes (wire format) after the 12-byte header
     * directly into query_name. No in-kernel parsing — userspace handles it.
     * The first byte will be a label-length (e.g., 0x03 for "www"),
     * which the Go reader uses to detect raw vs. parsed format.
     */
    __builtin_memset(&evt->query_name, 0, sizeof(evt->query_name));

    __u64 name_off = DNS_HEADER_LEN;
    __u64 name_len = iov_len - DNS_HEADER_LEN;
    if (name_len > MAX_DNS_NAME)
        name_len = MAX_DNS_NAME;

    /* Single bounded read — very verifier-friendly */
    bpf_probe_read_user(evt->query_name, name_len & 0x7f, base + name_off);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
