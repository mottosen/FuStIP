// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Configurable filter (set by userspace via skeleton rodata)
#define MAX_COMM_FILTERS 8
const volatile char comm_filters[MAX_COMM_FILTERS][16] = {};
const volatile __u8 num_comm_filters = 0;

#include "../bpf_core.h"

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

SEC("raw_tracepoint/block_rq_insert")
int BPF_PROG(block_rq_insert, struct request *rq)
{
	if (!comm_matches())
		return 0;
	return handle_block_rq_insert(rq);
}

SEC("raw_tracepoint/block_rq_issue")
int BPF_PROG(block_rq_issue, struct request *rq)
{
	if (!comm_matches())
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
