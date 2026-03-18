// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Phantex — Process Execution Probe (execve)
//
// Attaches to sys_enter_execve and sys_exit_execve tracepoints.
// Captures: which binary a process is executing, with what arguments,
// and whether the exec succeeded.
//
// This is the most important probe — it's how we discover AI agent processes
// (e.g., "python3 -m langchain ...") and track process creation.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../include/events.h"
#include "../include/maps.h"

/* ─── Temporary storage for execve enter data ─────────────────────────────── */
/*
 * sys_enter_execve gives us filename + argv.
 * sys_exit_execve gives us the return code.
 * We need to correlate them by TID (thread ID).
 *
 * Store the enter data in a per-CPU hash map, keyed by TID.
 * On exit, look it up, merge with retcode, and emit the full event.
 */

struct exec_enter_data {
    char filename[MAX_FILENAME];
    char argv[MAX_ARGV_LEN];
    __u32 ppid;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);   /* TID */
    __type(value, struct exec_enter_data);
} exec_enter_map SEC(".maps");

/*
 * Per-CPU array used as a "heap" for large structs that exceed the
 * BPF 512-byte stack limit. We look up index 0 to get a scratch buffer.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct exec_enter_data);
} exec_heap SEC(".maps");

/* ─── sys_enter_execve ────────────────────────────────────────────────────── */
/*
 * Tracepoint args for syscalls/sys_enter_execve:
 *   const char *filename
 *   const char *const *argv
 *   const char *const *envp
 */

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    /* Check PID filter */
    if (!should_track_pid(pid))
        return 0;

    /* Use per-CPU heap to avoid blowing the 512-byte BPF stack limit */
    __u32 zero = 0;
    struct exec_enter_data *data = bpf_map_lookup_elem(&exec_heap, &zero);
    if (!data)
        return 0;

    __builtin_memset(data, 0, sizeof(*data));

    /* Read filename (first arg to execve) */
    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&data->filename, sizeof(data->filename), filename_ptr);

    /* Read first argv entry (argv[1] — first real argument) */
    const char *const *argv_ptr = (const char *const *)ctx->args[1];
    if (argv_ptr) {
        const char *arg1 = NULL;
        bpf_probe_read_user(&arg1, sizeof(arg1), &argv_ptr[1]);
        if (arg1) {
            bpf_probe_read_user_str(&data->argv, sizeof(data->argv), arg1);
        }
    }

    /* Read parent PID from task_struct via CO-RE */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data->ppid = BPF_CORE_READ(task, real_parent, tgid);

    /* Store for correlation with sys_exit_execve */
    bpf_map_update_elem(&exec_enter_map, &tid, data, BPF_ANY);

    return 0;
}

/* ─── sys_exit_execve ─────────────────────────────────────────────────────── */

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;

    /* Look up the enter data we stored */
    struct exec_enter_data *enter = bpf_map_lookup_elem(&exec_enter_map, &tid);
    if (!enter)
        return 0;  /* no matching enter — skip */

    /* Reserve space in ring buffer */
    struct ph_exec_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        bpf_map_delete_elem(&exec_enter_map, &tid);
        return 0;  /* ring buffer full — drop event (counter in Go) */
    }

    /* Fill common header */
    fill_header(&evt->hdr, EVENT_PROCESS_EXEC);
    evt->hdr.ppid = enter->ppid;

    /* Fill exec-specific fields */
    __builtin_memcpy(&evt->filename, &enter->filename, sizeof(evt->filename));
    __builtin_memcpy(&evt->argv, &enter->argv, sizeof(evt->argv));
    evt->retcode = ctx->ret;
    evt->is_exit = 1;
    evt->_pad[0] = 0;
    evt->_pad[1] = 0;
    evt->_pad[2] = 0;

    /* Submit event */
    bpf_ringbuf_submit(evt, 0);

    /* Clean up enter map */
    bpf_map_delete_elem(&exec_enter_map, &tid);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
