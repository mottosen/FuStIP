// SPDX-License-Identifier: GPL-2.0
#ifndef __BLOCK_BPF_CORE_H
#define __BLOCK_BPF_CORE_H

#include "event.h"

// ── Per-request metadata stored across probes ──
struct rq_data {
	__u8  op;
	__u32 bytes;
	__u64 sector;
	__u8  comm[16];
};

// ── Per-(op, comm) key for inflight counters ──
struct inflight_key {
	__u8  op;
	char  comm[16];
};

// ── Maps ──

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, __u64);
} insert_time SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, __u64);
} issue_time SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct rq_data);
} rq_metadata SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 28); // 256 MB
} events SEC(".maps");

// Per-(op, comm) queue inflight counter (insert -> issue)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct inflight_key);
	__type(value, __s64);
} q_inflight_counts SEC(".maps");

// Per-(op, comm) driver inflight counter (issue -> complete)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct inflight_key);
	__type(value, __s64);
} d_inflight_counts SEC(".maps");

// ── Inline probe handlers ──

static __always_inline int handle_block_rq_insert(struct request *rq)
{
	__u64 rq_key = (__u64)rq;
	__u64 ts = bpf_ktime_get_ns();
	__u8 op = BPF_CORE_READ(rq, cmd_flags) & 0xFF;
	__u32 bytes = BPF_CORE_READ(rq, __data_len);
	__u64 sector = BPF_CORE_READ(rq, __sector);

	// Store insert time
	bpf_map_update_elem(&insert_time, &rq_key, &ts, BPF_ANY);

	// Store metadata for later probes
	struct rq_data data = {
		.op = op,
		.bytes = bytes,
		.sector = sector,
	};
	bpf_get_current_comm(&data.comm, sizeof(data.comm));
	bpf_map_update_elem(&rq_metadata, &rq_key, &data, BPF_ANY);

	// Atomically increment queue inflight; snapshot driver inflight
	struct inflight_key ikey = {};
	ikey.op = op;
	__builtin_memcpy(ikey.comm, data.comm, 16);
	__s64 zero = 0;
	bpf_map_update_elem(&q_inflight_counts, &ikey, &zero, BPF_NOEXIST);
	__s64 *qcnt = bpf_map_lookup_elem(&q_inflight_counts, &ikey);
	__s32 qi = 0;
	if (qcnt)
		qi = (__s32)(__sync_fetch_and_add(qcnt, 1) + 1);
	bpf_map_update_elem(&d_inflight_counts, &ikey, &zero, BPF_NOEXIST);
	__s64 *dcnt = bpf_map_lookup_elem(&d_inflight_counts, &ikey);
	__s32 di = 0;
	if (dcnt)
		di = (__s32)*dcnt;

	// Emit insert event
	struct block_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (e) {
		e->timestamp_ns = ts;
		e->event_type = EVT_INSERT;
		e->op = op;
		e->bytes = bytes;
		e->latency_ns = 0;
		e->sector = sector;
		e->rq = rq_key;
		__builtin_memcpy(e->comm, data.comm, 16);
		e->q_inflight = qi;
		e->d_inflight = di;
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

static __always_inline int handle_block_rq_issue(struct request *rq)
{
	__u64 rq_key = (__u64)rq;
	__u64 now = bpf_ktime_get_ns();
	__u8 op = BPF_CORE_READ(rq, cmd_flags) & 0xFF;
	__u32 bytes = BPF_CORE_READ(rq, __data_len);
	__u64 sector = BPF_CORE_READ(rq, __sector);

	// Store issue time (for complete probe)
	bpf_map_update_elem(&issue_time, &rq_key, &now, BPF_ANY);

	// Update metadata in case of changes (e.g. merging)
	struct rq_data data = {
		.op = op,
		.bytes = bytes,
		.sector = sector,
	};

	// Preserve comm from insert if available, else capture current
	struct rq_data *old_data = bpf_map_lookup_elem(&rq_metadata, &rq_key);
	if (old_data)
		__builtin_memcpy(data.comm, old_data->comm, 16);
	else
		bpf_get_current_comm(&data.comm, sizeof(data.comm));
	bpf_map_update_elem(&rq_metadata, &rq_key, &data, BPF_ANY);

	// Compute queue latency (insert → issue)
	__u64 queue_lat = 0;
	__u64 *t_insert = bpf_map_lookup_elem(&insert_time, &rq_key);
	if (t_insert) {
		queue_lat = now - *t_insert;
		bpf_map_delete_elem(&insert_time, &rq_key);
	}

	// Decrement queue inflight only if this request went through insert;
	// on schedulers like 'none', requests skip insert entirely.
	struct inflight_key ikey = {};
	ikey.op = op;
	__builtin_memcpy(ikey.comm, data.comm, 16);
	__s64 *qcnt = bpf_map_lookup_elem(&q_inflight_counts, &ikey);
	__s32 qi = 0;
	if (qcnt) {
		if (t_insert)
			qi = (__s32)(__sync_fetch_and_add(qcnt, -1) - 1);
		else
			qi = (__s32)*qcnt;
	}
	// Always increment driver inflight
	__s64 zero = 0;
	bpf_map_update_elem(&d_inflight_counts, &ikey, &zero, BPF_NOEXIST);
	__s64 *dcnt = bpf_map_lookup_elem(&d_inflight_counts, &ikey);
	__s32 di = 0;
	if (dcnt)
		di = (__s32)(__sync_fetch_and_add(dcnt, 1) + 1);

	// Emit issue event
	struct block_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (e) {
		e->timestamp_ns = now;
		e->event_type = EVT_ISSUE;
		e->op = op;
		e->bytes = bytes;
		e->latency_ns = queue_lat;
		e->sector = sector;
		e->rq = rq_key;
		__builtin_memcpy(e->comm, data.comm, 16);
		e->q_inflight = qi;
		e->d_inflight = di;
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

static __always_inline int handle_block_rq_complete(struct request *rq)
{
	__u64 rq_key = (__u64)rq;

	// Lookup issue time — if missing, this request wasn't tracked
	__u64 *t_issue = bpf_map_lookup_elem(&issue_time, &rq_key);
	if (!t_issue)
		return 0;

	__u64 now = bpf_ktime_get_ns();
	__u64 driver_lat = now - *t_issue;

	// Lookup stored metadata
	struct rq_data *data = bpf_map_lookup_elem(&rq_metadata, &rq_key);
	if (!data) {
		bpf_map_delete_elem(&issue_time, &rq_key);
		return 0;
	}

	// Snapshot queue inflight; atomically decrement driver inflight
	struct inflight_key ikey = {};
	ikey.op = data->op;
	__builtin_memcpy(ikey.comm, data->comm, 16);
	__s64 *qcnt = bpf_map_lookup_elem(&q_inflight_counts, &ikey);
	__s32 qi = 0;
	if (qcnt)
		qi = (__s32)*qcnt;
	__s64 *dcnt = bpf_map_lookup_elem(&d_inflight_counts, &ikey);
	__s32 di = 0;
	if (dcnt)
		di = (__s32)(__sync_fetch_and_add(dcnt, -1) - 1);

	// Emit complete event
	struct block_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (e) {
		e->timestamp_ns = now;
		e->event_type = EVT_COMPLETE;
		e->op = data->op;
		e->bytes = data->bytes;
		e->latency_ns = driver_lat;
		e->sector = data->sector;
		e->rq = rq_key;
		__builtin_memcpy(e->comm, data->comm, 16);
		e->q_inflight = qi;
		e->d_inflight = di;
		bpf_ringbuf_submit(e, 0);
	}

	// Cleanup maps
	bpf_map_delete_elem(&issue_time, &rq_key);
	bpf_map_delete_elem(&rq_metadata, &rq_key);

	return 0;
}

#endif // __BLOCK_BPF_CORE_H
