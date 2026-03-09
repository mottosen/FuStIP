// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Configurable filter (set by userspace via skeleton rodata)
const volatile char dev_filter[32] = {};
const volatile bool has_dev_filter = false;

#include "../bpf_core.h"

// ── Device filter helper ──
// Checks if the request's disk name contains the filter string
static __always_inline bool dev_matches(struct request *req) {
  if (!has_dev_filter)
    return true;

  char disk_name[32];
  struct gendisk *disk = BPF_CORE_READ(req, q, disk);
  if (!disk)
    return false;
  bpf_probe_read_kernel_str(&disk_name, sizeof(disk_name), &disk->disk_name);

  // Substring search
  for (int i = 0; i < 32; i++) {
    if (disk_name[i] == '\0')
      break;
    bool match = true;
    for (int j = 0; j < 32 && dev_filter[j] != '\0'; j++) {
      if (i + j >= 32 || disk_name[i + j] != dev_filter[j]) {
        match = false;
        break;
      }
    }
    if (match)
      return true;
  }
  return false;
}

SEC("fentry/nvme_setup_cmd")
int BPF_PROG(nvme_setup_cmd, void *ns, struct request *req) {
  if (!dev_matches(req))
    return 0;
  return handle_nvme_fentry_setup(req);
}

SEC("raw_tracepoint/nvme_setup_cmd")
int BPF_PROG(nvme_rawtp_setup) {
  // No filtering here — fentry already filtered.
  // Just pick up the rq pointer from the fentry bridge.
  return handle_nvme_rawtp_setup();
}

SEC("raw_tracepoint/nvme_complete_rq")
int BPF_PROG(nvme_complete_rq, struct request *req) {
  // No device filter on complete — matches by map entry
  return handle_nvme_complete(req);
}

char LICENSE[] SEC("license") = "GPL";
