// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Configurable filter (set by userspace via skeleton rodata)
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

// Nested-AND hierarchy: container ⊇ {comm, pid} (fs has no device tier).
// Each unset tier is a pass-through; the process tier is comm OR pid (union).
static __always_inline bool should_trace(void)
{
	return mntns_matches() && proc_matches();
}

// ── read() ──

SEC("tp/syscalls/sys_enter_read")
int handle_enter_read(struct trace_event_raw_sys_enter *ctx)
{
	if (!should_trace())
		return 0;
	__s32 fd = (__s32)ctx->args[0];
	__s64 count = (__s64)ctx->args[2];
	return handle_sc_enter(SC_READ, fd, -1, count);
}

SEC("tp/syscalls/sys_exit_read")
int handle_exit_read(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

// ── write() ──

SEC("tp/syscalls/sys_enter_write")
int handle_enter_write(struct trace_event_raw_sys_enter *ctx)
{
	if (!should_trace())
		return 0;
	__s32 fd = (__s32)ctx->args[0];
	__s64 count = (__s64)ctx->args[2];
	return handle_sc_enter(SC_WRITE, fd, -1, count);
}

SEC("tp/syscalls/sys_exit_write")
int handle_exit_write(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

// ── pread64() ──

SEC("tp/syscalls/sys_enter_pread64")
int handle_enter_pread64(struct trace_event_raw_sys_enter *ctx)
{
	if (!should_trace())
		return 0;
	__s32 fd = (__s32)ctx->args[0];
	__s64 count = (__s64)ctx->args[2];
	__s64 offset = (__s64)ctx->args[3];
	return handle_sc_enter(SC_PREAD64, fd, offset, count);
}

SEC("tp/syscalls/sys_exit_pread64")
int handle_exit_pread64(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

// ── pwrite64() ──

SEC("tp/syscalls/sys_enter_pwrite64")
int handle_enter_pwrite64(struct trace_event_raw_sys_enter *ctx)
{
	if (!should_trace())
		return 0;
	__s32 fd = (__s32)ctx->args[0];
	__s64 count = (__s64)ctx->args[2];
	__s64 offset = (__s64)ctx->args[3];
	return handle_sc_enter(SC_PWRITE64, fd, offset, count);
}

SEC("tp/syscalls/sys_exit_pwrite64")
int handle_exit_pwrite64(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

// ── openat() ──

SEC("tp/syscalls/sys_enter_openat")
int handle_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	if (!should_trace())
		return 0;
	__s32 dirfd = (__s32)ctx->args[0];
	return handle_sc_enter(SC_OPENAT, dirfd, -1, 0);
}

SEC("tp/syscalls/sys_exit_openat")
int handle_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

// ── close() ──

SEC("tp/syscalls/sys_enter_close")
int handle_enter_close(struct trace_event_raw_sys_enter *ctx)
{
	if (!should_trace())
		return 0;
	__s32 fd = (__s32)ctx->args[0];
	return handle_sc_enter(SC_CLOSE, fd, -1, 0);
}

SEC("tp/syscalls/sys_exit_close")
int handle_exit_close(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

// ── lseek() ──

SEC("tp/syscalls/sys_enter_lseek")
int handle_enter_lseek(struct trace_event_raw_sys_enter *ctx)
{
	if (!should_trace())
		return 0;
	__s32 fd = (__s32)ctx->args[0];
	__s64 offset = (__s64)ctx->args[1];
	return handle_sc_enter(SC_LSEEK, fd, offset, 0);
}

SEC("tp/syscalls/sys_exit_lseek")
int handle_exit_lseek(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

// ── newfstatat() ──

SEC("tp/syscalls/sys_enter_newfstatat")
int handle_enter_newfstatat(struct trace_event_raw_sys_enter *ctx)
{
	if (!should_trace())
		return 0;
	__s32 dirfd = (__s32)ctx->args[0];
	return handle_sc_enter(SC_NEWFSTATAT, dirfd, -1, 0);
}

SEC("tp/syscalls/sys_exit_newfstatat")
int handle_exit_newfstatat(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

// ── newfstat() ──

SEC("tp/syscalls/sys_enter_newfstat")
int handle_enter_newfstat(struct trace_event_raw_sys_enter *ctx)
{
	if (!should_trace())
		return 0;
	__s32 fd = (__s32)ctx->args[0];
	return handle_sc_enter(SC_NEWFSTAT, fd, -1, 0);
}

SEC("tp/syscalls/sys_exit_newfstat")
int handle_exit_newfstat(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

// ── unlinkat() ──

SEC("tp/syscalls/sys_enter_unlinkat")
int handle_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	if (!should_trace())
		return 0;
	__s32 dirfd = (__s32)ctx->args[0];
	return handle_sc_enter(SC_UNLINKAT, dirfd, -1, 0);
}

SEC("tp/syscalls/sys_exit_unlinkat")
int handle_exit_unlinkat(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

// ── mkdirat() ──

SEC("tp/syscalls/sys_enter_mkdirat")
int handle_enter_mkdirat(struct trace_event_raw_sys_enter *ctx)
{
	if (!should_trace())
		return 0;
	__s32 dirfd = (__s32)ctx->args[0];
	return handle_sc_enter(SC_MKDIRAT, dirfd, -1, 0);
}

SEC("tp/syscalls/sys_exit_mkdirat")
int handle_exit_mkdirat(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

// ── mmap() ──

SEC("tp/syscalls/sys_enter_mmap")
int handle_enter_mmap(struct trace_event_raw_sys_enter *ctx)
{
	if (!should_trace())
		return 0;
	__s64 length = (__s64)ctx->args[1];
	__s32 fd = (__s32)ctx->args[4];
	__s64 offset = (__s64)ctx->args[5];
	return handle_sc_enter(SC_MMAP, fd, offset, length);
}

SEC("tp/syscalls/sys_exit_mmap")
int handle_exit_mmap(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

// ── munmap() ──

SEC("tp/syscalls/sys_enter_munmap")
int handle_enter_munmap(struct trace_event_raw_sys_enter *ctx)
{
	if (!should_trace())
		return 0;
	__s64 length = (__s64)ctx->args[1];
	return handle_sc_enter(SC_MUNMAP, -1, -1, length);
}

SEC("tp/syscalls/sys_exit_munmap")
int handle_exit_munmap(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

// ── io_uring_enter() ──
//
// The submit/reap boundary for io_uring applications. One call can push many SQEs and/or wait
// for completions, so this is NOT one event per I/O — it fires per batch, at roughly the rate
// the application submits, which is well below the block/NVMe event rate.
//
// The generic fs_event fields are reused rather than widening the struct for one syscall:
//   fd     = args[0]  the ring fd (not a file)
//   bytes  = args[1]  to_submit — number of SQEs submitted, NOT a byte count
//   offset = args[2]  min_complete — number of completions waited for
// `bytes` is safe to overload because the byte/latency distributions are computed over an
// explicit allowlist of I/O syscalls (IO_SYSCALLS in generate_detailed_stats.py) that this is
// not a member of; it lands in counters.sc_count only. to_submit is worth keeping: it is the
// observed submission batch size, i.e. direct evidence of the queue depth the application
// actually asked for, independent of whatever its configuration claims.
SEC("tp/syscalls/sys_enter_io_uring_enter")
int handle_enter_io_uring_enter(struct trace_event_raw_sys_enter *ctx)
{
	if (!should_trace())
		return 0;
	__s32 ring_fd = (__s32)ctx->args[0];
	__s64 to_submit = (__s64)ctx->args[1];
	__s64 min_complete = (__s64)ctx->args[2];
	return handle_sc_enter(SC_IO_URING_ENTER, ring_fd, min_complete, to_submit);
}

SEC("tp/syscalls/sys_exit_io_uring_enter")
int handle_exit_io_uring_enter(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

// ── io_submit() / io_getevents()  (libaio) ──
//
// The other asynchronous data path, and the one the DiskANN reference reader is built on.
// Same rationale as io_uring_enter: an application using these issues no read/pread64 at all,
// so the classic syscall set reports zero I/O for it. Same column overloading, so the two
// async families read the same way:
//
//   io_submit(ctx, nr, iocbpp)                 bytes = nr        (iocbs submitted)
//   io_getevents(ctx, min_nr, nr, ev, tmo)     bytes = nr        (max events reaped)
//                                              offset = min_nr   (events waited for)
//
// `fd` stays -1 for both: the first argument is an aio_context_t, not a descriptor. Splitting
// submit from reap matters — io_submit returns as soon as the iocbs are queued, while
// io_getevents is where the thread actually blocks, so it is the reap side that carries the
// waiting time a latency breakdown wants.
SEC("tp/syscalls/sys_enter_io_submit")
int handle_enter_io_submit(struct trace_event_raw_sys_enter *ctx)
{
	if (!should_trace())
		return 0;
	__s64 nr = (__s64)ctx->args[1];
	return handle_sc_enter(SC_IO_SUBMIT, -1, -1, nr);
}

SEC("tp/syscalls/sys_exit_io_submit")
int handle_exit_io_submit(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_io_getevents")
int handle_enter_io_getevents(struct trace_event_raw_sys_enter *ctx)
{
	if (!should_trace())
		return 0;
	__s64 min_nr = (__s64)ctx->args[1];
	__s64 nr = (__s64)ctx->args[2];
	return handle_sc_enter(SC_IO_GETEVENTS, -1, min_nr, nr);
}

SEC("tp/syscalls/sys_exit_io_getevents")
int handle_exit_io_getevents(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

char LICENSE[] SEC("license") = "GPL";
