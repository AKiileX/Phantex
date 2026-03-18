// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Phantex — Memory Map Probe (mmap)
//
// Attaches to sys_enter_mmap tracepoint.
// Captures: address, length, and protection flags.
//
// Useful for detecting:
//   - Executable memory mapping (PROT_EXEC) — potential code injection
//   - Large memory allocations — resource abuse
//   - Suspicious RWX mappings (PROT_READ | PROT_WRITE | PROT_EXEC)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "../include/events.h"
#include "../include/maps.h"

/* Protection flag constants (from <asm-generic/mman-common.h>) */
#define PROT_EXEC   0x4

/* ─── sys_enter_mmap ──────────────────────────────────────────────────────── */
/*
 * Tracepoint args for syscalls/sys_enter_mmap:
 *   unsigned long addr
 *   unsigned long len
 *   unsigned long prot
 *   unsigned long flags
 *   unsigned long fd
 *   unsigned long off
 *
 * We only emit events for PROT_EXEC mappings to reduce noise.
 * Normal mmap (heap/stack) is uninteresting for security.
 */

SEC("tracepoint/syscalls/sys_enter_mmap")
int tracepoint__syscalls__sys_enter_mmap(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!should_track_pid(pid))
        return 0;

    __u32 prot  = (__u32)ctx->args[2];
    __u32 flags = (__u32)ctx->args[3];

    /*
     * Only emit events for executable mappings.
     * Normal mmap for heap/data is too noisy and not security-relevant.
     */
    if (!(prot & PROT_EXEC))
        return 0;

    struct ph_mmap_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    fill_header(&evt->hdr, EVENT_MEMORY_MAP);
    evt->addr   = (__u64)ctx->args[0];
    evt->length = (__u64)ctx->args[1];
    evt->prot   = prot;
    evt->flags  = flags;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
