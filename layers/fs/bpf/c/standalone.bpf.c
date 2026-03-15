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

// ── read() ──

SEC("tp/syscalls/sys_enter_read")
int handle_enter_read(struct trace_event_raw_sys_enter *ctx)
{
	if (!comm_matches())
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
	if (!comm_matches())
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
	if (!comm_matches())
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
	if (!comm_matches())
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
	if (!comm_matches())
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
	if (!comm_matches())
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
	if (!comm_matches())
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
	if (!comm_matches())
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
	if (!comm_matches())
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
	if (!comm_matches())
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
	if (!comm_matches())
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
	if (!comm_matches())
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
	if (!comm_matches())
		return 0;
	__s64 length = (__s64)ctx->args[1];
	return handle_sc_enter(SC_MUNMAP, -1, -1, length);
}

SEC("tp/syscalls/sys_exit_munmap")
int handle_exit_munmap(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

char LICENSE[] SEC("license") = "GPL";
