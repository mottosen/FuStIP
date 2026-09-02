// SPDX-License-Identifier: GPL-2.0
#ifndef __NVME_BPF_CORE_H
#define __NVME_BPF_CORE_H

#include "event.h"

// SLBA sentinel for commands with no logical block address (flush, or an
// unclassified opcode). Mirrors SECTOR_UNSET in generate_detailed_stats.py and
// matches the (u64)-1 the block layer leaves in rq->__sector for passthrough.
#define SECTOR_UNSET 0xFFFFFFFFFFFFFFFFULL

// NVMe command wire layout (UAPI-stable; the nvme_setup_cmd tracepoint's 2nd arg
// points at one of these). `struct nvme_command` lives only in nvme_core module
// BTF, not vmlinux.h, so we mirror just the rw prefix we read: opcode at byte 0,
// slba (__le64) at byte 40. All NVMe command types share opcode at byte 0.
struct nvme_cmd_wire {
  __u8  opcode;
  __u8  flags;
  __u16 command_id;
  __u32 nsid;
  __u32 cdw2;
  __u32 cdw3;
  __u64 metadata;
  __u64 prp1;
  __u64 prp2;
  __u64 slba;
} __attribute__((packed));

// NVMe NVM-command-set wire opcodes (drivers/nvme: read=0x02, write=0x01, …).
#define NVME_CMD_FLUSH 0x00
#define NVME_CMD_WRITE 0x01
#define NVME_CMD_READ 0x02
#define NVME_CMD_WRITE_ZEROES 0x08
#define NVME_CMD_DSM 0x09

// Normalize the NVMe wire opcode into the stable NVME_OP_* enum used downstream.
// Unmapped opcodes → 0xFF ("unknown"); must NOT fall through to 0 (= read).
static __always_inline __u8 nvme_opcode_to_op(__u8 opcode) {
  switch (opcode) {
  case NVME_CMD_FLUSH:         return NVME_OP_FLUSH;
  case NVME_CMD_WRITE:         return NVME_OP_WRITE;
  case NVME_CMD_READ:          return NVME_OP_READ;
  case NVME_CMD_WRITE_ZEROES:  return NVME_OP_WRITE_ZEROS;
  case NVME_CMD_DSM:           return NVME_OP_DISCARD;
  default:                     return 0xFF;
  }
}

// ── Per-command metadata stored between setup and complete ──
// comm/mntns/tid are captured in the SUBMITTER's context at fentry setup and carried to the
// completion probe, which runs in NVMe interrupt context where `current` is not the submitter.
struct cmd_data {
  __u8 op;
  __u32 bytes;
  __u64 sector;
  __u64 mntns_id;
  __u8 comm[16];
  char disk_name[32];      // kernel gendisk name, read once at fentry setup
  __u16 qid;               // NVMe queue id, read once at fentry setup
  __u32 tid;               // submitting thread id, read once at fentry setup
  __s32 inflight_at_setup; // queue depth for this (op, comm) when the command was issued
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
  __uint(max_entries, 1 << 29); // 512 MB default; override at load time with -b
} events SEC(".maps");

// Per-event-type counters: [type*2] = generated, [type*2+1] = dropped
// NVMe: setup=0,1  complete=2,3
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 4);
  __type(key, __u32);
  __type(value, __u64);
} event_counters SEC(".maps");

// Per-(op, comm) inflight counter (atomically incremented/decremented)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, struct inflight_key);
  __type(value, __s64);
} inflight_counts SEC(".maps");

// ── Untracked completions ──
// A completion whose command was never tracked at setup (filtered out by
// device/proc/container at nvme_setup_cmd, or — rarely — the setup probe was
// missed). Counted per (disk, op) so excluded other-disk traffic (filter
// working) can be told apart from target-disk setup misses.
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

// Called from fentry:nvme_setup_cmd — captures metadata and bridges to
// rawtracepoint
static __always_inline int handle_nvme_fentry_setup(struct request *req) {
  __u64 rq_key = (__u64)req;
  __u64 tid = bpf_get_current_pid_tgid();
  __u32 bytes = BPF_CORE_READ(req, __data_len);

  // op/sector are NOT read from the request here: passthrough (io_uring_cmd)
  // never populates rq->cmd_flags / rq->__sector. They are filled from the NVMe
  // command at the nvme_setup_cmd rawtracepoint below. Seed as "unknown"/unset.
  struct cmd_data data = {
      .op = 0xFF,
      .bytes = bytes,
      .sector = SECTOR_UNSET,
  };
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  data.mntns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
  bpf_get_current_comm(&data.comm, sizeof(data.comm));
  // Same tid the bridge below keys on, but kept in the event: the completion probe cannot
  // recover it. For io_uring this is whichever thread reached the driver — the app thread on
  // the inline submit path, an iou-wrk-* worker when the SQE was offloaded.
  data.tid = (__u32)tid;
  struct gendisk *disk = BPF_CORE_READ(req, q, disk);
  if (disk)
    bpf_probe_read_kernel_str(&data.disk_name, sizeof(data.disk_name), &disk->disk_name);

  // NVMe queue id, mirroring the kernel's nvme_req_qid(): admin commands (no
  // queuedata) are qid 0; I/O commands are the hw queue index + 1.
  void *qdata = BPF_CORE_READ(req, q, queuedata);
  data.qid = qdata ? (BPF_CORE_READ(req, mq_hctx, queue_num) + 1) : 0;

  bpf_map_update_elem(&cmd_metadata, &rq_key, &data, BPF_ANY);

  // Bridge: store rq pointer for the rawtracepoint to pick up
  bpf_map_update_elem(&fentry_rq, &tid, &rq_key, BPF_ANY);

  return 0;
}

// Called from rawtracepoint:nvme_setup_cmd — records accurate timestamp, reads
// the real op/SLBA from the NVMe command, and emits the setup event. `cmd` is
// the tracepoint's 2nd arg (struct nvme_command *), typed void* since that
// struct is module-BTF-only.
static __always_inline int handle_nvme_rawtp_setup(void *cmd) {
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

  // op/SLBA come from the actual NVMe command (correct for normal block IO and
  // io_uring_cmd passthrough alike). slba is __le64 — read natively on the
  // little-endian host. SLBA only meaningful for read/write.
  if (cmd) {
    struct nvme_cmd_wire c = {};
    bpf_probe_read_kernel(&c, sizeof(c), cmd);
    __u8 op = nvme_opcode_to_op(c.opcode);
    data->op = op;
    data->sector = (op == NVME_OP_READ || op == NVME_OP_WRITE) ? c.slba : SECTOR_UNSET;
  }

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

  // Stash the setup-time depth for the completion probe to emit. Not recoverable
  // later — see the comment on nvme_event.inflight_at_setup.
  data->inflight_at_setup = cur_inflight;

  // NO ring-buffer record here. Count the command as submitted and return: the
  // completion probe emits the single record carrying both ends of its life.
  // This counter is still what `cmd_setup` reports, and the difference against
  // the completion counter is how many commands were still in flight at teardown.
  __u32 gen_key = 0;
  __u64 *gen_cnt = bpf_map_lookup_elem(&event_counters, &gen_key);
  if (gen_cnt) (*gen_cnt)++;

  return 0;
}

// Called from rawtracepoint:nvme_complete_rq
static __always_inline int handle_nvme_complete(struct request *req) {
  __u64 rq_key = (__u64)req;

  // Lookup setup timestamp — if missing, this command wasn't tracked
  __u64 *t_setup = bpf_map_lookup_elem(&cmd_time, &rq_key);
  if (!t_setup) {
    // Untracked completion: count it per (disk, op). The request was never
    // recorded at setup, so read disk + op fresh from it here.
    struct untracked_key uk = {};
    uk.op = BPF_CORE_READ(req, cmd_flags) & 0xFF;
    struct gendisk *disk = BPF_CORE_READ(req, q, disk);
    if (disk)
      bpf_probe_read_kernel_str(&uk.disk_name, sizeof(uk.disk_name), &disk->disk_name);
    // Fall back to "?" when the gendisk/name is unreadable, so the untracked map
    // has no blank-keyed entry (e.g. a passthrough completion with no gendisk).
    if (uk.disk_name[0] == '\0') {
      uk.disk_name[0] = '?';
      uk.disk_name[1] = '\0';
    }
    __u64 zero = 0;
    bpf_map_update_elem(&untracked_completes, &uk, &zero, BPF_NOEXIST);
    __u64 *uc = bpf_map_lookup_elem(&untracked_completes, &uk);
    if (uc)
      __sync_fetch_and_add(uc, 1);
    return 0;
  }

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
  __u32 gen_key = 2;  // COMPLETE_GEN
  __u64 *gen_cnt = bpf_map_lookup_elem(&event_counters, &gen_key);
  if (gen_cnt) (*gen_cnt)++;

  struct nvme_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (e) {
    e->timestamp_ns = now;
    e->mntns_id = data->mntns_id;
    e->op = data->op;
    e->bytes = data->bytes;
    e->latency_ns = latency;
    e->sector = data->sector;
    e->rq = rq_key;
    __builtin_memcpy(e->comm, data->comm, 16);
    e->tid = data->tid;
    e->inflight_at_setup = data->inflight_at_setup;
    e->inflight = cur_inflight;
    e->qid = data->qid;
    __builtin_memcpy(e->disk_name, data->disk_name, 32);
    bpf_ringbuf_submit(e, 0);
  } else {
    __u32 drop_key = 3;  // COMPLETE_DROP
    __u64 *drop_cnt = bpf_map_lookup_elem(&event_counters, &drop_key);
    if (drop_cnt) (*drop_cnt)++;
  }

  // Cleanup maps
  bpf_map_delete_elem(&cmd_time, &rq_key);
  bpf_map_delete_elem(&cmd_metadata, &rq_key);

  return 0;
}

#endif // __NVME_BPF_CORE_H
