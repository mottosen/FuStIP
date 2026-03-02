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
#define SC_MAX        13

// ── Event struct (ring buffer → userspace) ──
struct fs_event {
	__u64 timestamp_ns;
	__u8  event_type;   // EVT_ENTER, EVT_EXIT
	__u8  syscall;      // SC_* index
	__s64 bytes;        // count/ret value; 0 if N/A
	__u64 latency_ns;   // enter→exit (only on exit)
	__s32 fd;           // file descriptor (-1 if N/A)
	__s64 offset;       // file offset (-1 if N/A)
	__u32 tid;          // thread ID (correlation key)
} __attribute__((packed));

#endif // __FS_EVENT_H
