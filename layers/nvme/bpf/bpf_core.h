// SPDX-License-Identifier: GPL-2.0
#ifndef __NVME_BPF_CORE_H
#define __NVME_BPF_CORE_H

#include "event.h"

// ── Per-command metadata stored between setup and complete ──
struct cmd_data {
  __u8 op;
  __u32 bytes;
  __u64 sector;
  __u8 comm[16];
};

// ── Per-(op, comm) key for inflight counters ──
struct inflight_key {
  __u8  op;
  char  comm[16];
};

// ── Maps ──

// fentry → rawtracepoint bridge: tid → rq pointer
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u64);
  __type(value, __u64);
} fentry_rq SEC(".maps");

// Setup timestamp: rq → nsec
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16384);
  __type(key, __u64);
  __type(value, __u64);
} cmd_time SEC(".maps");

// Per-command metadata: rq → cmd_data
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16384);
  __type(key, __u64);
  __type(value, struct cmd_data);
} cmd_metadata SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 28); // 256 MB
} events SEC(".maps");

// Per-(op, comm) inflight counter (atomically incremented/decremented)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, struct inflight_key);
  __type(value, __s64);
} inflight_counts SEC(".maps");

// ── Inline probe handlers ──

// Called from fentry:nvme_setup_cmd — captures metadata and bridges to
// rawtracepoint
static __always_inline int handle_nvme_fentry_setup(struct request *req) {
  __u64 rq_key = (__u64)req;
  __u64 tid = bpf_get_current_pid_tgid();
  __u8 op = BPF_CORE_READ(req, cmd_flags) & 0xFF;
  __u32 bytes = BPF_CORE_READ(req, __data_len);
  __u64 sector = BPF_CORE_READ(req, __sector);

  // Store metadata for complete probe
  struct cmd_data data = {
      .op = op,
      .bytes = bytes,
      .sector = sector,
  };
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  bpf_map_update_elem(&cmd_metadata, &rq_key, &data, BPF_ANY);

  // Bridge: store rq pointer for the rawtracepoint to pick up
  bpf_map_update_elem(&fentry_rq, &tid, &rq_key, BPF_ANY);

  return 0;
}

// Called from rawtracepoint:nvme_setup_cmd — records accurate timestamp and
// emits setup event
static __always_inline int handle_nvme_rawtp_setup(void) {
  __u64 tid = bpf_get_current_pid_tgid();

  // Pick up rq pointer from fentry bridge
  __u64 *rq_ptr = bpf_map_lookup_elem(&fentry_rq, &tid);
  if (!rq_ptr)
    return 0;

  __u64 rq_key = *rq_ptr;
  bpf_map_delete_elem(&fentry_rq, &tid);

  // Record accurate timestamp
  __u64 ts = bpf_ktime_get_ns();
  bpf_map_update_elem(&cmd_time, &rq_key, &ts, BPF_ANY);

  // Lookup metadata for event emission
  struct cmd_data *data = bpf_map_lookup_elem(&cmd_metadata, &rq_key);
  if (!data)
    return 0;

  // Atomically increment inflight counter (outside ringbuf reserve so
  // counter stays accurate even when ring buffer drops events)
  struct inflight_key ikey = {};
  ikey.op = data->op;
  __builtin_memcpy(ikey.comm, data->comm, 16);
  __s64 zero = 0;
  bpf_map_update_elem(&inflight_counts, &ikey, &zero, BPF_NOEXIST);
  __s64 *cnt = bpf_map_lookup_elem(&inflight_counts, &ikey);
  __s32 cur_inflight = 0;
  if (cnt)
    cur_inflight = (__s32)(__sync_fetch_and_add(cnt, 1) + 1);

  // Emit setup event
  struct nvme_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (e) {
    e->timestamp_ns = ts;
    e->event_type = EVT_SETUP;
    e->op = data->op;
    e->bytes = data->bytes;
    e->latency_ns = 0;
    e->sector = data->sector;
    e->rq = rq_key;
    __builtin_memcpy(e->comm, data->comm, 16);
    e->inflight = cur_inflight;
    bpf_ringbuf_submit(e, 0);
  }

  return 0;
}

// Called from rawtracepoint:nvme_complete_rq
static __always_inline int handle_nvme_complete(struct request *req) {
  __u64 rq_key = (__u64)req;

  // Lookup setup timestamp — if missing, this command wasn't tracked
  __u64 *t_setup = bpf_map_lookup_elem(&cmd_time, &rq_key);
  if (!t_setup)
    return 0;

  __u64 now = bpf_ktime_get_ns();
  __u64 latency = now - *t_setup;

  // Lookup stored metadata
  struct cmd_data *data = bpf_map_lookup_elem(&cmd_metadata, &rq_key);
  if (!data) {
    bpf_map_delete_elem(&cmd_time, &rq_key);
    return 0;
  }

  // Atomically decrement inflight counter
  struct inflight_key ikey = {};
  ikey.op = data->op;
  __builtin_memcpy(ikey.comm, data->comm, 16);
  __s64 *cnt = bpf_map_lookup_elem(&inflight_counts, &ikey);
  __s32 cur_inflight = 0;
  if (cnt)
    cur_inflight = (__s32)(__sync_fetch_and_add(cnt, -1) - 1);

  // Emit complete event
  struct nvme_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (e) {
    e->timestamp_ns = now;
    e->event_type = EVT_COMPLETE;
    e->op = data->op;
    e->bytes = data->bytes;
    e->latency_ns = latency;
    e->sector = data->sector;
    e->rq = rq_key;
    __builtin_memcpy(e->comm, data->comm, 16);
    e->inflight = cur_inflight;
    bpf_ringbuf_submit(e, 0);
  }

  // Cleanup maps
  bpf_map_delete_elem(&cmd_time, &rq_key);
  bpf_map_delete_elem(&cmd_metadata, &rq_key);

  return 0;
}

#endif // __NVME_BPF_CORE_H
