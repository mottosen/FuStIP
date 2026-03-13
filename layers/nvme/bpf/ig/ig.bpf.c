// SPDX-License-Identifier: GPL-2.0
//
// Inspektor Gadget wrapper for NVMe layer tracing.
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

GADGET_TRACER(nvme, events, nvme_event);

SEC("fentry/nvme_setup_cmd")
int BPF_PROG(ig_nvme_setup_cmd, void *ns, struct request *req)
{
	u64 mntns_id = gadget_get_current_mntns_id();
	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;
	return handle_nvme_fentry_setup(req);
}

SEC("raw_tracepoint/nvme_setup_cmd")
int BPF_PROG(ig_nvme_rawtp_setup)
{
	return handle_nvme_rawtp_setup();
}

SEC("raw_tracepoint/nvme_complete_rq")
int BPF_PROG(ig_nvme_complete_rq, struct request *req)
{
	return handle_nvme_complete(req);
}

char LICENSE[] SEC("license") = "GPL";
