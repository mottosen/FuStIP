// SPDX-License-Identifier: GPL-2.0
#ifndef __NVME_EVENT_H
#define __NVME_EVENT_H

// ── Event types ──
#define EVT_SETUP 0
#define EVT_COMPLETE 1

// ── NVMe operation types (reuses block cmd_flags & 0xFF) ──
#define NVME_OP_READ 0
#define NVME_OP_WRITE 1
#define NVME_OP_FLUSH 2
#define NVME_OP_DISCARD 3
#define NVME_OP_WRITE_ZEROS 9

// ── Event struct (ring buffer → userspace) ──
struct nvme_event {
  __u64 timestamp_ns;
  __u64 mntns_id;   // mount namespace id of originating task (0 if unknown)
  __u8 event_type;  // EVT_SETUP, EVT_COMPLETE
  __u8 op;          // NVME_OP_*
  __u32 bytes;      // rq->__data_len
  __u64 latency_ns; // setup→complete latency (only on complete)
  __u64 sector;     // rq->__sector (LBA)
  __u64 rq;         // request pointer (correlation ID)
  char  comm[16];   // process name
  __s32 inflight;   // current in-flight count for this op
} __attribute__((packed));

#endif // __NVME_EVENT_H
