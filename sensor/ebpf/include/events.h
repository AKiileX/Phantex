/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Phantex — Event Structure Definitions
 *
 * Shared between eBPF probes (C) and Go userspace (via cilium/ebpf codegen).
 * Every event has a common header followed by type-specific fields.
 *
 * IMPORTANT: These structs must stay in sync with:
 *   - Go structs in sensor/internal/ebpf/events.go
 *   - Protobuf definitions in proto/phantex/events.proto
 */

#ifndef __PHANTEX_EVENTS_H
#define __PHANTEX_EVENTS_H

/* ─── Event Type Enum ─────────────────────────────────────────────────────── */
/*
 * All Phantex types use the "ph_" prefix to avoid collision with kernel types
 * pulled in through vmlinux.h (e.g., the kernel has its own struct event_header).
 */

enum ph_event_type {
    EVENT_PROCESS_EXEC     = 0,
    EVENT_PROCESS_EXIT     = 1,
    EVENT_FILE_OPEN        = 10,
    EVENT_FILE_WRITE       = 11,
    EVENT_FILE_READ        = 12,
    EVENT_NETWORK_CONNECT  = 20,
    EVENT_NETWORK_ACCEPT   = 21,
    EVENT_NETWORK_DNS      = 22,
    EVENT_MEMORY_MAP       = 30,
};

/* ─── Common Event Header ─────────────────────────────────────────────────── */
/*
 * Every event starts with this header. The Go reader parses the header first,
 * then switches on event_type to parse the remaining payload.
 *
 * Total header size: 48 bytes (aligned).
 */

#define TASK_COMM_LEN   16
#define MAX_FILENAME    256
#define MAX_ARGV_LEN    256
#define MAX_DNS_NAME    128

struct ph_event_hdr {
    __u64 timestamp_ns;     /* ktime_get_boot_ns() — monotonic, survives sleep */
    __u32 event_type;       /* enum ph_event_type */
    __u32 pid;              /* process ID (tgid in kernel terms) */
    __u32 tid;              /* thread ID (pid in kernel terms) */
    __u32 uid;              /* user ID */
    __u32 ppid;             /* parent process ID */
    __u32 _pad;             /* alignment padding */
    char  comm[TASK_COMM_LEN]; /* process name (e.g., "python3") */
};

/* ─── Process Execution Event ─────────────────────────────────────────────── */
/*
 * Captured at sys_enter_execve (args) and sys_exit_execve (return code).
 * Two events per exec: enter has filename+argv, exit has retcode.
 */

struct ph_exec_event {
    struct ph_event_hdr hdr;
    char   filename[MAX_FILENAME];  /* binary being executed */
    char   argv[MAX_ARGV_LEN];     /* first argument (truncated) */
    __s32  retcode;                 /* 0 = success (only on exit event) */
    __u8   is_exit;                 /* 0 = enter, 1 = exit */
    __u8   _pad[3];
};

/* ─── Process Exit Event ──────────────────────────────────────────────────── */

struct ph_exit_event {
    struct ph_event_hdr hdr;
    __s32  exit_code;              /* process exit code */
    __u32  signal;                 /* signal that killed it (0 if normal exit) */
    __u64  duration_ns;            /* time from exec to exit */
};

/* ─── File Open Event ─────────────────────────────────────────────────────── */

struct ph_file_open_event {
    struct ph_event_hdr hdr;
    char   filename[MAX_FILENAME];
    __s32  flags;                  /* O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, etc. */
    __s32  retcode;                /* file descriptor or -errno */
};

/* ─── File Write Event ────────────────────────────────────────────────────── */
/*
 * We capture byte count only — NEVER file content (privacy, ADR-009).
 */

struct ph_file_write_event {
    struct ph_event_hdr hdr;
    __s32  fd;                     /* file descriptor */
    __u64  byte_count;             /* bytes written */
    __s32  retcode;                /* bytes actually written or -errno */
    __u32  _pad;
};

/* ─── File Read Event ─────────────────────────────────────────────────────── */

struct ph_file_read_event {
    struct ph_event_hdr hdr;
    __s32  fd;                     /* file descriptor */
    __u64  byte_count;             /* bytes requested */
    __s32  retcode;                /* bytes actually read or -errno */
    __u32  _pad;
};

/* ─── Network Connect Event ───────────────────────────────────────────────── */

struct ph_net_connect_event {
    struct ph_event_hdr hdr;
    __u32  src_addr;               /* source IPv4 (network byte order) */
    __u32  dst_addr;               /* destination IPv4 (network byte order) */
    __u16  src_port;               /* source port (host byte order) */
    __u16  dst_port;               /* destination port (host byte order) */
    __u8   protocol;               /* IPPROTO_TCP = 6, IPPROTO_UDP = 17 */
    __u8   ip_version;             /* 4 or 6 */
    __u8   _pad[2];
    /* IPv6 addresses (only used when ip_version == 6) */
    __u8   src_addr6[16];
    __u8   dst_addr6[16];
};

/* ─── Network Accept Event ────────────────────────────────────────────────── */

struct ph_net_accept_event {
    struct ph_event_hdr hdr;
    __u32  src_addr;
    __u32  dst_addr;
    __u16  src_port;
    __u16  dst_port;
    __u8   protocol;
    __u8   ip_version;
    __u8   _pad[2];
    __u8   src_addr6[16];
    __u8   dst_addr6[16];
};

/* ─── DNS Resolution Event ────────────────────────────────────────────────── */
/*
 * Captured from UDP sendmsg to port 53. We extract the DNS query name.
 */

struct ph_dns_event {
    struct ph_event_hdr hdr;
    char   query_name[MAX_DNS_NAME]; /* DNS domain being resolved */
    __u16  query_type;               /* A=1, AAAA=28, CNAME=5, etc. */
    __u16  dst_port;                 /* should always be 53 */
    __u32  dst_addr;                 /* DNS server IP */
};

/* ─── Memory Map Event ────────────────────────────────────────────────────── */

struct ph_mmap_event {
    struct ph_event_hdr hdr;
    __u64  addr;                   /* requested address (0 = kernel chooses) */
    __u64  length;                 /* mapping length */
    __u32  prot;                   /* PROT_READ, PROT_WRITE, PROT_EXEC */
    __u32  flags;                  /* MAP_PRIVATE, MAP_SHARED, MAP_ANONYMOUS */
};

#endif /* __PHANTEX_EVENTS_H */
