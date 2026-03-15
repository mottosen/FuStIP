// SPDX-License-Identifier: GPL-2.0
#ifndef __BLOCK_EVENT_H
#define __BLOCK_EVENT_H

// ── Event types ──
#define EVT_INSERT  0
#define EVT_ISSUE   1
#define EVT_COMPLETE 2

// ── Block operation types (cmd_flags & 0xFF) ──
#define BLK_OP_READ        0
#define BLK_OP_WRITE       1
#define BLK_OP_FLUSH       2
#define BLK_OP_DISCARD     3
#define BLK_OP_WRITE_ZEROS 9

// ── Event struct (ring buffer → userspace) ──
struct block_event {
	__u64 timestamp_ns;
	__u8  event_type;   // EVT_INSERT, EVT_ISSUE, EVT_COMPLETE
	__u8  op;           // BLK_OP_*
	__u32 bytes;        // rq->__data_len
	__u64 latency_ns;   // queue lat (issue), driver lat (complete), 0 (insert)
	__u64 sector;       // rq->__sector
	__u64 rq;           // request pointer (correlation ID)
	__u8  comm[16];     // process name
	__s32 q_inflight;   // queue inflight (insert -> issue)
	__s32 d_inflight;   // driver inflight (issue -> complete)
} __attribute__((packed));

#endif // __BLOCK_EVENT_H
