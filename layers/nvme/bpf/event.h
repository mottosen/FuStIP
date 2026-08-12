// SPDX-License-Identifier: GPL-2.0
#ifndef __NVME_EVENT_H
#define __NVME_EVENT_H

// ── One record per command ──
//
// The layer emits ONE ring-buffer record per NVMe command, at completion. Nothing
// about the submission is lost: op, bytes, sector, comm, tid, disk_name and qid are
// captured at setup into cmd_data and copied out unchanged, and the setup time is
// exactly `timestamp_ns - latency_ns`. The one value that is neither carried nor
// derivable is the setup-time queue depth, so it is a field of its own
// (`inflight_at_setup` below).
//
// One record rather than two per command is what makes the layer usable under load.
// Measured on a 2x24-core host: one consumer sustains ~2.03 M events/s alone but
// only ~1.47 M/s once the block and fs collectors run beside it. A workload
// offering 1.40 M/s therefore sat ~5 % under that ceiling and lost events on every
// burst. One record per command puts the offered rate at 0.70 M/s, and pairs with
// the 512 MB ring for ~6.4 s of burst absorption.
//
// Correlation is kernel-side (cmd_time / cmd_metadata, keyed by the request pointer)
// and latency is computed in BPF, so userspace never pairs anything. Commands that
// never complete emit nothing and are accounted for by
// (setup_generated - complete_generated) in counters.json.

// ── NVMe operation types ──
// Stable enum used in the CSV/stats; the BPF setup probe normalizes the NVMe
// wire opcode (read=0x02, write=0x01, …) into these values, so they are correct
// for both normal block IO and io_uring_cmd passthrough. 0xFF → "unknown".
#define NVME_OP_READ 0
#define NVME_OP_WRITE 1
#define NVME_OP_FLUSH 2
#define NVME_OP_DISCARD 3
#define NVME_OP_WRITE_ZEROS 9

// ── Event struct (ring buffer → userspace) ──
// Emitted once, at completion. 107 bytes.
struct nvme_event {
  __u64 timestamp_ns;  // COMPLETION time; setup time = timestamp_ns - latency_ns
  __u64 mntns_id;      // mount namespace id of originating task (0 if unknown)
  __u8 op;             // NVME_OP_* (normalized from the NVMe wire opcode)
  __u32 bytes;         // rq->__data_len
  __u64 latency_ns;    // setup→complete latency
  __u64 sector;        // SLBA in logical-block units (read/write); else (u64)-1
  __u64 rq;            // request pointer (correlation ID)
  char  comm[16];      // process name
  __u32 tid;           // SUBMITTING thread id (captured at setup, carried to complete)
  // Queue depth for this (op, comm) at the two ends of the command's life.
  //
  // inflight_at_setup CANNOT be derived from inflight: the counter is shared per
  // (op, comm) and every concurrent sibling mutates it in between, so there is no
  // arithmetic that recovers "depth when this command was issued" from "depth after
  // this command completed". Depth-at-submission is what any queueing analysis
  // needs, so it is carried explicitly rather than left to be reconstructed.
  __s32 inflight_at_setup; // post-increment, at setup
  __s32 inflight;          // post-decrement, at completion
  __u16 qid;           // NVMe queue id (0 = admin, 1..N = I/O queues)
  char  disk_name[32]; // kernel gendisk name (e.g. "nvme0n1")
} __attribute__((packed));

#endif // __NVME_EVENT_H
