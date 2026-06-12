// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Configurable filter (set by userspace via skeleton rodata)
#define MAX_DEV_FILTERS 8
const volatile char dev_filters[MAX_DEV_FILTERS][32] = {};
const volatile __u8 num_dev_filters = 0;
#define MAX_COMM_FILTERS 8
const volatile char comm_filters[MAX_COMM_FILTERS][16] = {};
const volatile __u8 num_comm_filters = 0;
#define MAX_PID_FILTERS 8
const volatile __u32 pid_filters[MAX_PID_FILTERS] = {};
const volatile __u8 num_pid_filters = 0;
const volatile bool filter_by_mntns = false;

#include "../bpf_core.h"

// ── Mount namespace filter map (populated dynamically by loader) ──
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u32);
	__uint(max_entries, 32);
} mntns_filter SEC(".maps");
static __always_inline bool mntns_matches(void)
{
	if (!filter_by_mntns)
		return true;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 mntns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	return bpf_map_lookup_elem(&mntns_filter, &mntns_id) != NULL;
}

// ── Comm filter helper ──
// Returns true if current task's comm contains any filter substring
static __always_inline bool comm_matches(void)
{
	if (num_comm_filters == 0)
		return true;

	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));

	for (int f = 0; f < MAX_COMM_FILTERS; f++) {
		if (f >= num_comm_filters)
			break;
		if (comm_filters[f][0] == '\0')
			continue;
		// Substring search: check if comm_filters[f] is contained in comm
		for (int i = 0; i < 16; i++) {
			if (comm[i] == '\0')
				break;
			bool match = true;
			for (int j = 0; j < 16 && comm_filters[f][j] != '\0'; j++) {
				if (i + j >= 16 || comm[i + j] != comm_filters[f][j]) {
					match = false;
					break;
				}
			}
			if (match)
				return true;
		}
	}
	return false;
}

// ── PID filter helper ──
// Returns true if current task's tgid matches any filter pid
static __always_inline bool pid_matches(void)
{
	if (num_pid_filters == 0)
		return true;

	__u32 tgid = bpf_get_current_pid_tgid() >> 32;

	for (int f = 0; f < MAX_PID_FILTERS; f++) {
		if (f >= num_pid_filters)
			break;
		if (pid_filters[f] == tgid)
			return true;
	}
	return false;
}

// ── Process tier (comm OR pid, union) ──
// Pass-through when neither filter is set; otherwise match if the task matches
// any *active* filter (each consulted only when non-empty).
static __always_inline bool proc_matches(void)
{
	if (num_comm_filters == 0 && num_pid_filters == 0)
		return true;
	if (num_comm_filters > 0 && comm_matches())
		return true;
	if (num_pid_filters > 0 && pid_matches())
		return true;
	return false;
}

// ── Device filter helper ──
// Returns true if the request's disk name contains any filter substring
static __always_inline bool dev_matches(struct request *rq)
{
	if (num_dev_filters == 0)
		return true;

	char disk_name[32];
	struct gendisk *disk = BPF_CORE_READ(rq, q, disk);
	if (!disk)
		return false;
	bpf_probe_read_kernel_str(&disk_name, sizeof(disk_name), &disk->disk_name);

	for (int f = 0; f < MAX_DEV_FILTERS; f++) {
		if (f >= num_dev_filters)
			break;
		if (dev_filters[f][0] == '\0')
			continue;
		for (int i = 0; i < 32; i++) {
			if (disk_name[i] == '\0')
				break;
			bool match = true;
			for (int j = 0; j < 32 && dev_filters[f][j] != '\0'; j++) {
				if (i + j >= 32 || disk_name[i + j] != dev_filters[f][j]) {
					match = false;
					break;
				}
			}
			if (match)
				return true;
		}
	}
	return false;
}

// Nested-AND hierarchy: container ⊇ device ⊇ {comm, pid}.
// Each unset tier is a pass-through; the process tier is comm OR pid (union).
static __always_inline bool should_trace(struct request *rq)
{
	return mntns_matches() && dev_matches(rq) && proc_matches();
}

SEC("raw_tracepoint/block_rq_insert")
int BPF_PROG(block_rq_insert, struct request *rq)
{
	if (!should_trace(rq))
		return 0;
	return handle_block_rq_insert(rq);
}

SEC("raw_tracepoint/block_rq_issue")
int BPF_PROG(block_rq_issue, struct request *rq)
{
	if (!should_trace(rq))
		return 0;
	return handle_block_rq_issue(rq);
}

SEC("raw_tracepoint/block_rq_complete")
int BPF_PROG(block_rq_complete, struct request *rq)
{
	// No comm filter on complete — matches by map entry
	return handle_block_rq_complete(rq);
}

char LICENSE[] SEC("license") = "GPL";
