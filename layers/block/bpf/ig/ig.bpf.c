// SPDX-License-Identifier: GPL-2.0
//
// Inspektor Gadget wrapper for block layer tracing.
// Kept minimal — shared logic lives in bpf_core.h.
//
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns.h>
#include <gadget/mntns_filter.h>

#include "../bpf_core.h"

GADGET_TRACER(block, events, block_event);

SEC("raw_tracepoint/block_rq_insert")
int BPF_PROG(ig_block_rq_insert, struct request *rq) {
  u64 mntns_id = gadget_get_current_mntns_id();
  if (gadget_should_discard_mntns_id(mntns_id))
    return 0;
  return handle_block_rq_insert(rq);
}

SEC("raw_tracepoint/block_rq_issue")
int BPF_PROG(ig_block_rq_issue, struct request *rq) {
  return handle_block_rq_issue(rq);
}

SEC("raw_tracepoint/block_rq_complete")
int BPF_PROG(ig_block_rq_complete, struct request *rq) {
  return handle_block_rq_complete(rq);
}

char LICENSE[] SEC("license") = "GPL";
