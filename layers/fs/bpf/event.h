// SPDX-License-Identifier: GPL-2.0
#ifndef __FS_EVENT_H
#define __FS_EVENT_H

// ── Event types ──
#define EVT_ENTER 0
#define EVT_EXIT  1

// ── Syscall indices ──
#define SC_READ       0
#define SC_WRITE      1
#define SC_PREAD64    2
#define SC_PWRITE64   3
#define SC_OPENAT     4
#define SC_CLOSE      5
#define SC_LSEEK      6
#define SC_NEWFSTATAT 7
#define SC_NEWFSTAT   8
#define SC_UNLINKAT   9
#define SC_MKDIRAT    10
#define SC_MMAP       11
#define SC_MUNMAP     12
// Asynchronous submission paths. An application using either of these does its reads without
// ever calling read/pread64, which is why a syscall tracer that stops at the classic calls
// reports zero I/O for it. `bytes`/`offset` carry the syscalls' own arguments here, not byte
// counts — see the struct comments below.
//
// Both families are traced because which one a workload uses is not knowable from the outside:
// io_uring for modern engines, libaio (io_submit/io_getevents) for everything built against
// the older interface — DiskANN's reference reader among them.
#define SC_IO_URING_ENTER 13
#define SC_IO_SUBMIT      14
#define SC_IO_GETEVENTS   15
#define SC_MAX        16

// ── Event struct (ring buffer → userspace) ──
struct fs_event {
	__u64 timestamp_ns;
	__u64 mntns_id;     // mount namespace id of originating task (0 if unknown)
	__u8  event_type;   // EVT_ENTER, EVT_EXIT
	__u8  syscall;      // SC_* index
	__s64 bytes;        // count/ret value; 0 if N/A. io_uring_enter: to_submit (SQEs), see below
	__u64 latency_ns;   // enter→exit (only on exit)
	__s32 fd;           // file descriptor (-1 if N/A). io_uring_enter: the ring fd
	__s64 offset;       // file offset (-1 if N/A). io_uring_enter: min_complete, see below
	__u32 tid;          // thread ID (correlation key)
	char  comm[16];     // process name
	__s32 inflight;     // current in-flight count for this syscall
} __attribute__((packed));

#endif // __FS_EVENT_H
