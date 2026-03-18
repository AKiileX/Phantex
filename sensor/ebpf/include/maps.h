/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Phantex — BPF Map Definitions
 *
 * All probes share these maps. The Go userspace populates the PID filter
 * and reads events from the ring buffer.
 *
 * Maps are pinned to /sys/fs/bpf/phantex/ so multiple probe programs
 * can share the same maps (loaded separately but all write to one ring buffer).
 */

#ifndef __PHANTEX_MAPS_H
#define __PHANTEX_MAPS_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* ─── Ring Buffer ─────────────────────────────────────────────────────────── */
/*
 * Single ring buffer for all event types. Go reads from this.
 * Size: 16 MB (handles ~100K events/sec burst without drops).
 * Pinned: /sys/fs/bpf/phantex/events
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024); /* 16 MB */
} events SEC(".maps");

/* ─── PID Filter Map ──────────────────────────────────────────────────────── */
/*
 * Hash map of PIDs we're tracking (AI agent processes).
 * Key: PID (__u32), Value: 1 (__u8, presence flag).
 *
 * If this map is empty, we track ALL processes (useful for dev/debug).
 * If populated, only matching PIDs generate events.
 *
 * Go userspace populates this from agent discovery (Block A3).
 * Pinned: /sys/fs/bpf/phantex/pid_filter
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);     /* max tracked PIDs */
    __type(key, __u32);
    __type(value, __u8);
} pid_filter SEC(".maps");

/* ─── Config Map ──────────────────────────────────────────────────────────── */
/*
 * Single-entry array map for runtime configuration from Go userspace.
 * Index 0 = config struct.
 */

struct phantex_config {
    __u8  filter_enabled;   /* 1 = only emit events for PIDs in pid_filter */
    __u8  _pad[7];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct phantex_config);
} config_map SEC(".maps");

/* ─── Helper: Check if PID should be tracked ──────────────────────────────── */
/*
 * Returns 1 if we should emit events for this PID, 0 if we should skip.
 *
 * Logic:
 *   - If filter is disabled (config.filter_enabled == 0): track everything
 *   - If filter is enabled: only track PIDs present in pid_filter map
 */
static __always_inline int should_track_pid(__u32 pid)
{
    __u32 key = 0;
    struct phantex_config *cfg;
    __u8 *val;

    cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg || !cfg->filter_enabled)
        return 1;  /* filter disabled — track all */

    val = bpf_map_lookup_elem(&pid_filter, &pid);
    return val ? 1 : 0;
}

/* ─── Helper: Fill event header ───────────────────────────────────────────── */
/*
 * Populates common fields for any event. Call this first in every probe.
 */
static __always_inline void fill_header(struct ph_event_hdr *hdr, __u32 event_type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    hdr->timestamp_ns = bpf_ktime_get_boot_ns();
    hdr->event_type   = event_type;
    hdr->pid          = pid_tgid >> 32;           /* tgid = userspace PID */
    hdr->tid          = (__u32)pid_tgid;          /* pid  = userspace TID */
    hdr->uid          = (__u32)uid_gid;
    hdr->ppid         = 0; /* filled per-probe where available via task_struct */
    hdr->_pad         = 0;

    bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));
}

#endif /* __PHANTEX_MAPS_H */
