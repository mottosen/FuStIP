// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Configurable filter (set by userspace via skeleton rodata)
#define MAX_DEV_FILTERS 8
const volatile char dev_filters[MAX_DEV_FILTERS][32] = {};
const volatile __u8 num_dev_filters = 0;
#define MAX_COMM_FILTERS 8
const volatile char comm_filters[MAX_COMM_FILTERS][16] = {};
const volatile __u8 num_comm_filters = 0;
const volatile bool filter_by_mntns = false;
const volatile bool filter_or_mode = false;

#include "../bpf_core.h"

// ── Mount namespace filter map (populated dynamically by loader) ──
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u64);
  __type(value, __u32);
  __uint(max_entries, 32);
} mntns_filter SEC(".maps");

static __always_inline bool mntns_matches(void) {
  if (!filter_by_mntns)
    return true;
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  __u64 mntns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
  return bpf_map_lookup_elem(&mntns_filter, &mntns_id) != NULL;
}

// ── Comm filter helper ──
// Returns true if current task's comm contains any filter substring
static __always_inline bool comm_matches(void) {
  if (num_comm_filters == 0)
    return true;

  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm));

  for (int f = 0; f < MAX_COMM_FILTERS; f++) {
    if (f >= num_comm_filters)
      break;
    if (comm_filters[f][0] == '\0')
      continue;
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

// ── Device filter helper ──
// Returns true if the request's disk name contains any filter substring
static __always_inline bool dev_matches(struct request *req) {
  if (num_dev_filters == 0)
    return true;

  char disk_name[32];
  struct gendisk *disk = BPF_CORE_READ(req, q, disk);
  if (!disk)
    return false;
  bpf_probe_read_kernel_str(&disk_name, sizeof(disk_name), &disk->disk_name);

  for (int f = 0; f < MAX_DEV_FILTERS; f++) {
    if (f >= num_dev_filters)
      break;
    if (dev_filters[f][0] == '\0')
      continue;
    // Substring search: check if dev_filters[f] is contained in disk_name
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

SEC("fentry/nvme_setup_cmd")
int BPF_PROG(nvme_setup_cmd, void *ns, struct request *req) {
  if (filter_or_mode) {
    // OR between host identification (dev AND comm) and container (mntns)
    bool host_match = dev_matches(req) && comm_matches();
    if (!host_match && !mntns_matches())
      return 0;
  } else {
    // AND: all active filters must independently match
    if (!dev_matches(req) || !comm_matches() || !mntns_matches())
      return 0;
  }
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
