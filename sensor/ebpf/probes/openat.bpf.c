// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Phantex — File Open Probe (openat)
//
// Attaches to sys_enter_openat and sys_exit_openat tracepoints.
// Captures: which files a process opens and with what flags.
//
// Critical for detecting:
//   - Sensitive file access (/etc/shadow, *.pem, *credentials*)
//   - Excessive file reads (exfiltration indicator)
//   - Unexpected file creation

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../include/events.h"
#include "../include/maps.h"

/* ─── Temporary storage for openat enter data ─────────────────────────────── */

struct openat_enter_data {
    char filename[MAX_FILENAME];
    __s32 flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);   /* TID */
    __type(value, struct openat_enter_data);
} openat_enter_map SEC(".maps");

/* ─── sys_enter_openat ────────────────────────────────────────────────────── */
/*
 * Tracepoint args for syscalls/sys_enter_openat:
 *   int dfd
 *   const char *filename
 *   int flags
 *   umode_t mode
 */

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    if (!should_track_pid(pid))
        return 0;

    struct openat_enter_data data = {};

    /* filename is the second arg (args[1]) */
    const char *filename_ptr = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename_ptr);

    /* flags is the third arg (args[2]) */
    data.flags = (__s32)ctx->args[2];

    bpf_map_update_elem(&openat_enter_map, &tid, &data, BPF_ANY);

    return 0;
}

/* ─── sys_exit_openat ─────────────────────────────────────────────────────── */

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    struct openat_enter_data *enter = bpf_map_lookup_elem(&openat_enter_map, &tid);
    if (!enter)
        return 0;

    struct ph_file_open_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        bpf_map_delete_elem(&openat_enter_map, &tid);
        return 0;
    }

    fill_header(&evt->hdr, EVENT_FILE_OPEN);

    __builtin_memcpy(&evt->filename, &enter->filename, sizeof(evt->filename));
    evt->flags   = enter->flags;
    evt->retcode = ctx->ret;  /* fd on success, -errno on failure */

    bpf_ringbuf_submit(evt, 0);
    bpf_map_delete_elem(&openat_enter_map, &tid);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
