// SPDX-License-Identifier: GPL-2.0
#ifndef __BLOCK_EVENT_H
#define __BLOCK_EVENT_H

// ── One record per request ──
//
// The layer emits ONE ring-buffer record per request, at completion, carrying
// everything needed to place the two earlier stages on the timeline:
//
//   issue time  = timestamp_ns - latency_ns
//   insert time = issue time  - queue_latency_ns   (only when BLK_F_QUEUED)
//
// The two waits are separate fields rather than one: `latency_ns` is always the
// driver's (issue -> complete) and `queue_latency_ns` always the scheduler's
// (insert -> issue), so neither has to be interpreted by context.
//
// The rate argument is the same as the nvme layer's: three collectors sharing a
// host drop each one's sustainable rate well below what it manages alone, and block
// was the second heaviest producer at 1.13 M records/s. One record per request
// takes it to 0.38 M/s.
//
// ── Flags ──
// Requests dispatched straight to the driver skip `insert` entirely (scheduler
// 'none', io_uring — the common case for the workloads this layer profiles).
// "No queue stage" would otherwise be indistinguishable from "queued with an
// immeasurably short wait", since both leave queue_latency_ns at zero.
// BLK_F_QUEUED records it explicitly,
// which is what keeps direct-dispatched requests out of the queue-latency
// distribution and makes the direct-dispatch fraction computable.
#define BLK_F_QUEUED (1 << 0)

// ── Block operation types (cmd_flags & 0xFF) ──
#define BLK_OP_READ        0
#define BLK_OP_WRITE       1
#define BLK_OP_FLUSH       2
#define BLK_OP_DISCARD     3
#define BLK_OP_WRITE_ZEROS 9

// ── Event struct (ring buffer → userspace) ──
// Emitted once, at completion. 90 bytes.
struct block_event {
	__u64 timestamp_ns;      // COMPLETION time
	__u64 mntns_id;          // mount namespace id of originating task (0 if unknown)
	__u8  op;                // BLK_OP_*
	__u8  flags;             // BLK_F_* (see above)
	__u32 bytes;             // rq->__data_len, as re-read at issue (post-merge)
	__u64 latency_ns;        // DRIVER latency: issue -> complete
	__u64 queue_latency_ns;  // QUEUE latency: insert -> issue; 0 unless BLK_F_QUEUED
	__u64 sector;            // rq->__sector, as re-read at issue (post-merge)
	__u64 rq;                // request pointer (correlation ID)
	char  comm[16];          // process name
	__u32 tid;               // SUBMITTING thread id (captured at insert/issue, carried here)
	// Depth snapshots at each stage this request itself passed through.
	//
	// These cannot be collapsed into one field or derived from each other: both
	// counters are shared per (op, comm) and every concurrent sibling mutates them
	// in between, so the value at completion says nothing about the value when this
	// request was inserted or issued. Carrying all four preserves the queue-depth
	// and driver-depth time series exactly, including the seconds that contain
	// submissions but no completions.
	__s32 q_inflight_at_insert;    // 0 when not queued
	__s32 q_inflight_at_issue;     // 0 when not queued
	__s32 d_inflight_at_issue;
	__s32 d_inflight_at_complete;
} __attribute__((packed));

#endif // __BLOCK_EVENT_H
