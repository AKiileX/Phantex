// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Phantex — File Write/Read Probe
//
// Attaches to sys_enter_write and sys_enter_read tracepoints.
// Captures: byte count and file descriptor. NEVER captures content (privacy).
//
// Critical for detecting:
//   - Large outbound data transfers (exfiltration)
//   - Unusual write patterns
//   - Excessive I/O that could indicate DoS

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "../include/events.h"
#include "../include/maps.h"

/* ─── sys_enter_write ─────────────────────────────────────────────────────── */
/*
 * Tracepoint args for syscalls/sys_enter_write:
 *   unsigned int fd
 *   const char *buf
 *   size_t count
 *
 * We capture fd + count. We NEVER read buf (privacy — ADR-009 Level 1).
 */

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!should_track_pid(pid))
        return 0;

    /* Skip writes to stdout/stderr (fd 1, 2) — too noisy */
    __s32 fd = (__s32)ctx->args[0];
    if (fd <= 2)
        return 0;

    __u64 count = (__u64)ctx->args[2];

    /* Skip tiny writes (< 64 bytes) to reduce noise */
    if (count < 64)
        return 0;

    struct ph_file_write_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    fill_header(&evt->hdr, EVENT_FILE_WRITE);
    evt->fd         = fd;
    evt->byte_count = count;
    evt->retcode    = 0;   /* not available on enter — would need exit probe */
    evt->_pad       = 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* ─── sys_enter_read ──────────────────────────────────────────────────────── */
/*
 * Tracepoint args for syscalls/sys_enter_read:
 *   unsigned int fd
 *   char *buf
 *   size_t count
 */

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint__syscalls__sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!should_track_pid(pid))
        return 0;

    /* Skip reads from stdin (fd 0) */
    __s32 fd = (__s32)ctx->args[0];
    if (fd <= 0)
        return 0;

    __u64 count = (__u64)ctx->args[2];

    /* Skip tiny reads to reduce noise */
    if (count < 64)
        return 0;

    struct ph_file_read_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    fill_header(&evt->hdr, EVENT_FILE_READ);
    evt->fd         = fd;
    evt->byte_count = count;
    evt->retcode    = 0;
    evt->_pad       = 0;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
