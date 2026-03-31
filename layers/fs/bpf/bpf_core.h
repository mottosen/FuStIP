// SPDX-License-Identifier: GPL-2.0
#ifndef __FS_BPF_CORE_H
#define __FS_BPF_CORE_H

#include "event.h"

// ── Per-syscall enter data stored for exit correlation ──
struct sc_enter_data {
	__u64 ts;
	__s32 fd;
	__s64 offset;
	__s64 bytes;    // count arg for IO syscalls, length for mmap
	__u64 mntns_id;
	__u8  sc_idx;
	__u8  comm[16];
};

// ── Per-(syscall, comm) key for inflight counters ──
struct inflight_key {
	__u8  sc_idx;
	char  comm[16];
};

// ── Maps ──

// Enter timestamp + args: tid → sc_enter_data
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct sc_enter_data);
} sc_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 28); // 256 MB
} events SEC(".maps");

// Per-event-type counters: [type*2] = generated, [type*2+1] = dropped
// FS: enter=0,1  exit=2,3
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} event_counters SEC(".maps");

// Per-(syscall, comm) inflight counter (atomically incremented/decremented)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct inflight_key);
	__type(value, __s64);
} inflight_counts SEC(".maps");

// ── Inline handlers ──

static __always_inline int handle_sc_enter(__u8 sc_idx, __s32 fd,
					   __s64 offset, __s64 bytes)
{
	__u64 tid = bpf_get_current_pid_tgid();
	__u64 ts = bpf_ktime_get_ns();

	// Store enter data for exit correlation
	struct sc_enter_data data = {
		.ts = ts,
		.fd = fd,
		.offset = offset,
		.bytes = bytes,
		.sc_idx = sc_idx,
	};
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	data.mntns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	bpf_get_current_comm(&data.comm, sizeof(data.comm));
	bpf_map_update_elem(&sc_start, &tid, &data, BPF_ANY);

	// Atomically increment inflight counter
	struct inflight_key ikey = {};
	ikey.sc_idx = sc_idx;
	__builtin_memcpy(ikey.comm, data.comm, 16);
	__s64 zero = 0;
	bpf_map_update_elem(&inflight_counts, &ikey, &zero, BPF_NOEXIST);
	__s64 *cnt = bpf_map_lookup_elem(&inflight_counts, &ikey);
	__s32 cur_inflight = 0;
	if (cnt)
		cur_inflight = (__s32)(__sync_fetch_and_add(cnt, 1) + 1);

	// Emit enter event
	__u32 gen_key = 0;
	__u64 *gen_cnt = bpf_map_lookup_elem(&event_counters, &gen_key);
	if (gen_cnt) (*gen_cnt)++;

	struct fs_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (e) {
		e->timestamp_ns = ts;
		e->mntns_id = data.mntns_id;
		e->event_type = EVT_ENTER;
		e->syscall = sc_idx;
		e->bytes = bytes;
		e->latency_ns = 0;
		e->fd = fd;
		e->offset = offset;
		e->tid = (__u32)tid;
		__builtin_memcpy(e->comm, data.comm, 16);
		e->inflight = cur_inflight;
		bpf_ringbuf_submit(e, 0);
	} else {
		__u32 drop_key = 1;
		__u64 *drop_cnt = bpf_map_lookup_elem(&event_counters, &drop_key);
		if (drop_cnt) (*drop_cnt)++;
	}

	return 0;
}

static __always_inline int handle_sc_exit(__s64 ret)
{
	__u64 tid = bpf_get_current_pid_tgid();

	struct sc_enter_data *data = bpf_map_lookup_elem(&sc_start, &tid);
	if (!data)
		return 0;

	__u64 now = bpf_ktime_get_ns();
	__u64 latency = now - data->ts;

	// Atomically decrement inflight counter
	struct inflight_key ikey = {};
	ikey.sc_idx = data->sc_idx;
	__builtin_memcpy(ikey.comm, data->comm, 16);
	__s64 *cnt = bpf_map_lookup_elem(&inflight_counts, &ikey);
	__s32 cur_inflight = 0;
	if (cnt)
		cur_inflight = (__s32)(__sync_fetch_and_add(cnt, -1) - 1);

	// Emit exit event
	__u32 gen_key2 = 2;  // EXIT_GEN
	__u64 *gen_cnt2 = bpf_map_lookup_elem(&event_counters, &gen_key2);
	if (gen_cnt2) (*gen_cnt2)++;

	struct fs_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (e) {
		e->timestamp_ns = now;
		e->mntns_id = data->mntns_id;
		e->event_type = EVT_EXIT;
		e->syscall = data->sc_idx;
		e->bytes = ret;
		e->latency_ns = latency;
		e->fd = data->fd;
		e->offset = data->offset;
		e->tid = (__u32)tid;
		__builtin_memcpy(e->comm, data->comm, 16);
		e->inflight = cur_inflight;
		bpf_ringbuf_submit(e, 0);
	} else {
		__u32 drop_key2 = 3;  // EXIT_DROP
		__u64 *drop_cnt2 = bpf_map_lookup_elem(&event_counters, &drop_key2);
		if (drop_cnt2) (*drop_cnt2)++;
	}

	bpf_map_delete_elem(&sc_start, &tid);

	return 0;
}

#endif // __FS_BPF_CORE_H
