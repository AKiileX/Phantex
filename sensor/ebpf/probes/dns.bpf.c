// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Phantex — DNS Resolution Probe
//
// Attaches to kprobe/udp_sendmsg to intercept DNS queries.
// Filters for port 53 (DNS) and extracts the query domain name.
//
// Critical for detecting:
//   - DNS-based exfiltration (data encoded in subdomain queries)
//   - Connections to suspicious domains
//   - C2 communication via DNS tunneling

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../include/events.h"
#include "../include/maps.h"

/* DNS header is 12 bytes, query name starts at byte 12 */
#define DNS_HEADER_LEN  12
#define DNS_PORT        53

/*
 * CO-RE flavor struct for older kernels (< 6.4) where iov_iter had a
 * member called "iov".  Newer kernels renamed it to "__iov".  The
 * triple-underscore suffix is the BPF CO-RE "type flavor" convention —
 * the relocator matches the base name (struct iov_iter) at load time.
 */
struct iov_iter___old {
    const struct iovec *iov;
};

/* ─── Helper: Parse DNS query name from wire format ───────────────────────── */
/*
 * DNS wire format: \x03www\x06google\x03com\x00
 * We convert to: www.google.com
 *
 * eBPF verifier requires bounded loops, so we limit to MAX_DNS_NAME.
 */
static __always_inline int parse_dns_name(
    const __u8 *dns_payload, int payload_len,
    char *out, int out_len)
{
    int i = 0;     /* position in dns_payload */
    int j = 0;     /* position in output string */
    __u8 label_len;

    /* Bounded loop — verifier demands a known upper limit */
    #pragma unroll
    for (int iter = 0; iter < 32; iter++) {
        if (i >= payload_len || i >= 253 || j >= out_len - 1)
            break;

        bpf_probe_read_kernel(&label_len, 1, &dns_payload[i]);
        if (label_len == 0)
            break;

        if (label_len > 63)  /* label too long — compressed or malformed */
            break;

        i++;  /* skip length byte */

        /* Add dot separator between labels (not before first) */
        if (j > 0 && j < out_len - 1) {
            out[j++] = '.';
        }

        /* Copy label bytes */
        #pragma unroll
        for (int k = 0; k < 63; k++) {
            if (k >= label_len || j >= out_len - 1 || i >= payload_len)
                break;
            __u8 ch;
            bpf_probe_read_kernel(&ch, 1, &dns_payload[i]);
            out[j++] = ch;
            i++;
        }
    }

    if (j < out_len)
        out[j] = '\0';

    return j;
}

/* ─── kprobe/udp_sendmsg — Intercept DNS queries ─────────────────────────── */
/*
 * udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
 *
 * We check if the destination port is 53 (DNS).
 * If so, we read the msghdr to get the DNS payload and parse the query name.
 */

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kprobe__udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!should_track_pid(pid))
        return 0;

    /* Check destination port — we only care about DNS (port 53) */
    __u16 dst_port = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (dst_port != DNS_PORT)
        return 0;

    /* Get destination address */
    __u32 dst_addr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

    /*
     * Read the DNS payload from the first iovec in the msghdr.
     * This is a simplified approach — real DNS packets could span multiple iovecs,
     * but for standard queries this works.
     *
     * CO-RE NOTE: In kernel < 6.4 the iov pointer is in iov_iter.__iov.
     * In kernel 6.4+ the struct iov_iter was refactored and __iov was renamed.
     * We guard with bpf_core_field_exists() to handle both kernel generations.
     */
    struct iov_iter *iter = &msg->msg_iter;
    const struct iovec *iov = NULL;

    /*
     * Kernel 6.4+ renamed iov_iter.iov → iov_iter.__iov.  We check for
     * __iov first (present in the vmlinux.h we compiled against) and fall
     * back to the old layout via the CO-RE flavor struct so the code
     * compiles on both kernel generations and relocates correctly at load.
     */
    if (bpf_core_field_exists(iter->__iov)) {
        bpf_probe_read_kernel(&iov, sizeof(iov), &iter->__iov);
    } else {
        bpf_probe_read_kernel(&iov, sizeof(iov),
            &((struct iov_iter___old *)iter)->iov);
    }
    if (!iov)
        return 0;

    /* Read the first iovec */
    struct iovec first_iov;
    bpf_probe_read_kernel(&first_iov, sizeof(first_iov), iov);

    void *base = first_iov.iov_base;
    __u64 iov_len = first_iov.iov_len;

    if (!base || iov_len < DNS_HEADER_LEN + 1)
        return 0;

    /* Read DNS payload (header + query) into stack buffer.
     * NOTE: dns_buf is DNS_HEADER_LEN + MAX_DNS_NAME = 12 + 128 = 140 bytes.
     * We must cap read_len to sizeof(dns_buf) exactly — using & 0xff (255)
     * would allow the verifier to prove safety but would read past the buffer
     * boundary on kernels that skip the size check. Use sizeof(dns_buf). */
    __u8 dns_buf[DNS_HEADER_LEN + MAX_DNS_NAME];
#define DNS_BUF_SIZE (DNS_HEADER_LEN + MAX_DNS_NAME)
    __u64 read_len = iov_len;
    if (read_len > DNS_BUF_SIZE)
        read_len = DNS_BUF_SIZE;

    if (bpf_probe_read_user(dns_buf, read_len & 0xff, base) < 0)
        return 0;

    /* Reserve ring buffer event */
    struct ph_dns_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    fill_header(&evt->hdr, EVENT_NETWORK_DNS);
    evt->dst_addr = dst_addr;
    evt->dst_port = DNS_PORT;

    /* Extract query type from DNS header flags (bytes 2-3) */
    evt->query_type = 0;
    /* Parse query name starting after DNS header (byte 12) */
    __builtin_memset(&evt->query_name, 0, sizeof(evt->query_name));

    int name_len = iov_len - DNS_HEADER_LEN;
    if (name_len > 0 && name_len < MAX_DNS_NAME) {
        parse_dns_name(&dns_buf[DNS_HEADER_LEN], name_len,
                       evt->query_name, sizeof(evt->query_name));
    }

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
