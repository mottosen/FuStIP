// SPDX-License-Identifier: GPL-2.0
#ifndef __BLOCK_BPF_CORE_H
#define __BLOCK_BPF_CORE_H

#include "event.h"

// ── Per-request metadata stored across probes ──
// comm/mntns/tid are captured in the SUBMITTER's context (insert, or issue when the request
// direct-dispatched past insert) and carried to the completion probe, which runs in interrupt
// context where `current` is not the submitting task.
// Only the completion probe emits a record, so everything the insert and issue
// stages observe that the completion probe cannot re-derive is stashed here and
// carried forward. queue_latency_ns and the two queue-depth snapshots are only
// meaningful when the request actually went through insert, which `flags` records.
struct rq_data {
	__u8  op;
	__u8  flags;                 // BLK_F_QUEUED once insert has fired
	__u32 bytes;
	__u64 sector;
	__u64 mntns_id;
	__u8  comm[16];
	__u32 tid;
	__u64 queue_latency_ns;      // insert -> issue, measured at issue
	__s32 q_inflight_at_insert;
	__s32 q_inflight_at_issue;
	__s32 d_inflight_at_issue;
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
	__uint(max_entries, 1 << 29); // 512 MB default; override at load time with -b
} events SEC(".maps");

// Counter slots: 0 = requests queued (reached insert), 2 = requests issued,
// 4 = completions emitted, 5 = completions dropped by a full ring.
// Slots 1 and 3 are unused: only the completion probe reserves a record.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 6);
	__type(key, __u32);
	__type(value, __u64);
} event_counters SEC(".maps");

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

// ── Untracked completions ──
// A completion whose request was never tracked at issue (filtered out by
// device/proc/container at issue, or — rarely — the issue probe was missed).
// Counted per (disk, op) so excluded other-disk traffic (filter working) can be
// told apart from target-disk issue misses.
struct untracked_key {
	char disk_name[32];
	__u8 op;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, struct untracked_key);
	__type(value, __u64);
} untracked_completes SEC(".maps");

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
		.flags = BLK_F_QUEUED,   // reaching insert IS what "queued" means
		.bytes = bytes,
		.sector = sector,
	};
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	data.mntns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	bpf_get_current_comm(&data.comm, sizeof(data.comm));
	data.tid = (__u32)bpf_get_current_pid_tgid();

	// Atomically increment queue inflight
	struct inflight_key ikey = {};
	ikey.op = op;
	__builtin_memcpy(ikey.comm, data.comm, 16);
	__s64 zero = 0;
	bpf_map_update_elem(&q_inflight_counts, &ikey, &zero, BPF_NOEXIST);
	__s64 *qcnt = bpf_map_lookup_elem(&q_inflight_counts, &ikey);
	if (qcnt)
		data.q_inflight_at_insert = (__s32)(__sync_fetch_and_add(qcnt, 1) + 1);
	// Ensure the driver counter exists so issue can increment it.
	bpf_map_update_elem(&d_inflight_counts, &ikey, &zero, BPF_NOEXIST);

	bpf_map_update_elem(&rq_metadata, &rq_key, &data, BPF_ANY);

	// No ring-buffer record: count the request as queued and let the completion
	// probe emit the single record. This counter is what `rq_queued` reports, and
	// (issued - queued) is the direct-dispatch count.
	__u32 gen_key = 0;
	__u64 *gen_cnt = bpf_map_lookup_elem(&event_counters, &gen_key);
	if (gen_cnt) (*gen_cnt)++;

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
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	data.mntns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	// Preserve comm/tid from insert if available, else capture current. The else branch is
	// the direct-dispatch path (scheduler 'none', io_uring) where insert never fired — it is
	// the common case for the workloads this layer exists to profile, so tid must be captured
	// here too or it would be null on exactly the I/O that matters.
	//
	// flags and q_inflight_at_insert must be carried across as well: `data` is a fresh
	// struct (op/bytes/sector are deliberately re-read here to catch scheduler merges),
	// so anything the insert stage recorded is lost unless copied forward. Dropping
	// BLK_F_QUEUED here would silently reclassify every queued request as direct-dispatched.
	struct rq_data *old_data = bpf_map_lookup_elem(&rq_metadata, &rq_key);
	if (old_data) {
		__builtin_memcpy(data.comm, old_data->comm, 16);
		data.mntns_id = old_data->mntns_id;
		data.tid = old_data->tid;
		data.flags = old_data->flags;
		data.q_inflight_at_insert = old_data->q_inflight_at_insert;
	} else {
		bpf_get_current_comm(&data.comm, sizeof(data.comm));
		data.tid = (__u32)bpf_get_current_pid_tgid();
	}

	// Compute queue latency (insert → issue)
	__u64 *t_insert = bpf_map_lookup_elem(&insert_time, &rq_key);
	if (t_insert) {
		data.queue_latency_ns = now - *t_insert;
		bpf_map_delete_elem(&insert_time, &rq_key);
	}

	// Decrement queue inflight only if this request went through insert;
	// on schedulers like 'none', requests skip insert entirely.
	struct inflight_key ikey = {};
	ikey.op = op;
	__builtin_memcpy(ikey.comm, data.comm, 16);
	__s64 *qcnt = bpf_map_lookup_elem(&q_inflight_counts, &ikey);
	if (qcnt) {
		if (t_insert)
			data.q_inflight_at_issue = (__s32)(__sync_fetch_and_add(qcnt, -1) - 1);
		else
			data.q_inflight_at_issue = (__s32)*qcnt;
	}
	// Always increment driver inflight
	__s64 zero = 0;
	bpf_map_update_elem(&d_inflight_counts, &ikey, &zero, BPF_NOEXIST);
	__s64 *dcnt = bpf_map_lookup_elem(&d_inflight_counts, &ikey);
	if (dcnt)
		data.d_inflight_at_issue = (__s32)(__sync_fetch_and_add(dcnt, 1) + 1);

	bpf_map_update_elem(&rq_metadata, &rq_key, &data, BPF_ANY);

	// No ring-buffer record here either. This counter is `rq_issued`.
	__u32 gen_key2 = 2;  // ISSUE_GEN
	__u64 *gen_cnt2 = bpf_map_lookup_elem(&event_counters, &gen_key2);
	if (gen_cnt2) (*gen_cnt2)++;

	return 0;
}

static __always_inline int handle_block_rq_complete(struct request *rq)
{
	__u64 rq_key = (__u64)rq;

	// Lookup issue time — if missing, this request wasn't tracked
	__u64 *t_issue = bpf_map_lookup_elem(&issue_time, &rq_key);
	if (!t_issue) {
		// Untracked completion: count it per (disk, op). The request was never
		// recorded at issue, so read disk + op fresh from it here.
		struct untracked_key uk = {};
		uk.op = BPF_CORE_READ(rq, cmd_flags) & 0xFF;
		struct gendisk *disk = BPF_CORE_READ(rq, q, disk);
		if (disk)
			bpf_probe_read_kernel_str(&uk.disk_name, sizeof(uk.disk_name), &disk->disk_name);
		__u64 zero = 0;
		bpf_map_update_elem(&untracked_completes, &uk, &zero, BPF_NOEXIST);
		__u64 *uc = bpf_map_lookup_elem(&untracked_completes, &uk);
		if (uc)
			__sync_fetch_and_add(uc, 1);
		return 0;
	}

	__u64 now = bpf_ktime_get_ns();
	__u64 driver_lat = now - *t_issue;

	// Lookup stored metadata
	struct rq_data *data = bpf_map_lookup_elem(&rq_metadata, &rq_key);
	if (!data) {
		bpf_map_delete_elem(&issue_time, &rq_key);
		return 0;
	}

	// Atomically decrement driver inflight
	struct inflight_key ikey = {};
	ikey.op = data->op;
	__builtin_memcpy(ikey.comm, data->comm, 16);
	__s64 *dcnt = bpf_map_lookup_elem(&d_inflight_counts, &ikey);
	__s32 di = 0;
	if (dcnt)
		di = (__s32)(__sync_fetch_and_add(dcnt, -1) - 1);

	// Emit the single record for this request's whole life
	__u32 gen_key3 = 4;  // COMPLETE_GEN
	__u64 *gen_cnt3 = bpf_map_lookup_elem(&event_counters, &gen_key3);
	if (gen_cnt3) (*gen_cnt3)++;

	struct block_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (e) {
		e->timestamp_ns = now;
		e->mntns_id = data->mntns_id;
		e->op = data->op;
		e->flags = data->flags;
		e->bytes = data->bytes;
		e->latency_ns = driver_lat;
		e->queue_latency_ns = data->queue_latency_ns;
		e->sector = data->sector;
		e->rq = rq_key;
		__builtin_memcpy(e->comm, data->comm, 16);
		e->tid = data->tid;
		e->q_inflight_at_insert = data->q_inflight_at_insert;
		e->q_inflight_at_issue = data->q_inflight_at_issue;
		e->d_inflight_at_issue = data->d_inflight_at_issue;
		e->d_inflight_at_complete = di;
		bpf_ringbuf_submit(e, 0);
	} else {
		__u32 drop_key3 = 5;  // COMPLETE_DROP
		__u64 *drop_cnt3 = bpf_map_lookup_elem(&event_counters, &drop_key3);
		if (drop_cnt3) (*drop_cnt3)++;
	}

	// Cleanup maps
	bpf_map_delete_elem(&issue_time, &rq_key);
	bpf_map_delete_elem(&rq_metadata, &rq_key);

	return 0;
}

#endif // __BLOCK_BPF_CORE_H
