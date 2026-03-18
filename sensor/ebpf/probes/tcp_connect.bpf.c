// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Phantex — Network Connection Probe (tcp_connect + inet_csk_accept)
//
// Attaches to kprobe/tcp_connect for outbound connections
// and kprobe/inet_csk_accept return for inbound connections.
//
// Critical for detecting:
//   - Data exfiltration (connections to unknown external IPs)
//   - Command & control communication
//   - Unexpected API calls from AI agents

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../include/events.h"
#include "../include/maps.h"

/* ─── Helper: Extract IPv4 socket info ────────────────────────────────────── */

static __always_inline void fill_ipv4_from_sock(
    struct sock *sk,
    __u32 *src_addr, __u32 *dst_addr,
    __u16 *src_port, __u16 *dst_port)
{
    *src_addr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    *dst_addr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    *src_port = BPF_CORE_READ(sk, __sk_common.skc_num);         /* host order */
    *dst_port = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport)); /* net→host */
}

/* ─── kprobe/tcp_connect — Outbound TCP connections ───────────────────────── */
/*
 * tcp_connect(struct sock *sk) is called when a TCP SYN is about to be sent.
 * This captures the moment an AI agent opens an outbound connection.
 */

SEC("kprobe/tcp_connect")
int BPF_KPROBE(kprobe__tcp_connect, struct sock *sk)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!should_track_pid(pid))
        return 0;

    /* Check address family — we handle IPv4 and IPv6 */
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

    struct ph_net_connect_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    fill_header(&evt->hdr, EVENT_NETWORK_CONNECT);
    evt->protocol = 6;  /* TCP */

    if (family == 2) {  /* AF_INET (IPv4) */
        evt->ip_version = 4;
        fill_ipv4_from_sock(sk, &evt->src_addr, &evt->dst_addr,
                           &evt->src_port, &evt->dst_port);
        __builtin_memset(&evt->src_addr6, 0, sizeof(evt->src_addr6));
        __builtin_memset(&evt->dst_addr6, 0, sizeof(evt->dst_addr6));
    } else if (family == 10) {  /* AF_INET6 */
        evt->ip_version = 6;
        evt->src_addr = 0;
        evt->dst_addr = 0;
        BPF_CORE_READ_INTO(&evt->src_addr6, sk,
                           __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(&evt->dst_addr6, sk,
                           __sk_common.skc_v6_daddr.in6_u.u6_addr8);
        evt->src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
        evt->dst_port = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
    } else {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    evt->_pad[0] = 0;
    evt->_pad[1] = 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* ─── kretprobe/inet_csk_accept — Inbound TCP connections ─────────────────── */
/*
 * inet_csk_accept() returns the newly accepted socket.
 * This captures inbound connections TO the AI agent (e.g., API server).
 */

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(kretprobe__inet_csk_accept, struct sock *sk)
{
    if (!sk)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!should_track_pid(pid))
        return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != 2 && family != 10)  /* AF_INET or AF_INET6 only */
        return 0;

    struct ph_net_accept_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    fill_header(&evt->hdr, EVENT_NETWORK_ACCEPT);
    evt->protocol = 6;  /* TCP */

    if (family == 2) {
        evt->ip_version = 4;
        fill_ipv4_from_sock(sk, &evt->src_addr, &evt->dst_addr,
                           &evt->src_port, &evt->dst_port);
        __builtin_memset(&evt->src_addr6, 0, sizeof(evt->src_addr6));
        __builtin_memset(&evt->dst_addr6, 0, sizeof(evt->dst_addr6));
    } else {
        evt->ip_version = 6;
        evt->src_addr = 0;
        evt->dst_addr = 0;
        BPF_CORE_READ_INTO(&evt->src_addr6, sk,
                           __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(&evt->dst_addr6, sk,
                           __sk_common.skc_v6_daddr.in6_u.u6_addr8);
        evt->src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
        evt->dst_port = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
    }

    evt->_pad[0] = 0;
    evt->_pad[1] = 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
