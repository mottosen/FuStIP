// SPDX-License-Identifier: GPL-2.0
//
// Inspektor Gadget wrapper for FS layer tracing.
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

GADGET_TRACER(fs, events, fs_event);

// ── mntns filter wrapper ──
// Only filter on enter (process context). Exit events rely on map
// lookup — if enter was filtered out, no map entry exists and
// handle_sc_exit returns early.

static __always_inline int ig_sc_enter(__u8 sc_idx, __s32 fd,
				       __s64 offset, __s64 bytes)
{
	u64 mntns_id = gadget_get_current_mntns_id();
	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;
	return handle_sc_enter(sc_idx, fd, offset, bytes);
}

// ── read/write ──

SEC("tp/syscalls/sys_enter_read")
int ig_enter_read(struct trace_event_raw_sys_enter *ctx)
{
	return ig_sc_enter(SC_READ, (__s32)ctx->args[0], -1,
			   (__s64)ctx->args[2]);
}

SEC("tp/syscalls/sys_exit_read")
int ig_exit_read(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_write")
int ig_enter_write(struct trace_event_raw_sys_enter *ctx)
{
	return ig_sc_enter(SC_WRITE, (__s32)ctx->args[0], -1,
			       (__s64)ctx->args[2]);
}

SEC("tp/syscalls/sys_exit_write")
int ig_exit_write(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

// ── pread64/pwrite64 ──

SEC("tp/syscalls/sys_enter_pread64")
int ig_enter_pread64(struct trace_event_raw_sys_enter *ctx)
{
	return ig_sc_enter(SC_PREAD64, (__s32)ctx->args[0],
			       (__s64)ctx->args[3], (__s64)ctx->args[2]);
}

SEC("tp/syscalls/sys_exit_pread64")
int ig_exit_pread64(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_pwrite64")
int ig_enter_pwrite64(struct trace_event_raw_sys_enter *ctx)
{
	return ig_sc_enter(SC_PWRITE64, (__s32)ctx->args[0],
			       (__s64)ctx->args[3], (__s64)ctx->args[2]);
}

SEC("tp/syscalls/sys_exit_pwrite64")
int ig_exit_pwrite64(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

// ── openat/close/lseek ──

SEC("tp/syscalls/sys_enter_openat")
int ig_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	return ig_sc_enter(SC_OPENAT, (__s32)ctx->args[0], -1, 0);
}

SEC("tp/syscalls/sys_exit_openat")
int ig_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_close")
int ig_enter_close(struct trace_event_raw_sys_enter *ctx)
{
	return ig_sc_enter(SC_CLOSE, (__s32)ctx->args[0], -1, 0);
}

SEC("tp/syscalls/sys_exit_close")
int ig_exit_close(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_lseek")
int ig_enter_lseek(struct trace_event_raw_sys_enter *ctx)
{
	return ig_sc_enter(SC_LSEEK, (__s32)ctx->args[0],
			       (__s64)ctx->args[1], 0);
}

SEC("tp/syscalls/sys_exit_lseek")
int ig_exit_lseek(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

// ── stat variants ──

SEC("tp/syscalls/sys_enter_newfstatat")
int ig_enter_newfstatat(struct trace_event_raw_sys_enter *ctx)
{
	return ig_sc_enter(SC_NEWFSTATAT, (__s32)ctx->args[0], -1, 0);
}

SEC("tp/syscalls/sys_exit_newfstatat")
int ig_exit_newfstatat(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_newfstat")
int ig_enter_newfstat(struct trace_event_raw_sys_enter *ctx)
{
	return ig_sc_enter(SC_NEWFSTAT, (__s32)ctx->args[0], -1, 0);
}

SEC("tp/syscalls/sys_exit_newfstat")
int ig_exit_newfstat(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

// ── unlinkat/mkdirat ──

SEC("tp/syscalls/sys_enter_unlinkat")
int ig_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	return ig_sc_enter(SC_UNLINKAT, (__s32)ctx->args[0], -1, 0);
}

SEC("tp/syscalls/sys_exit_unlinkat")
int ig_exit_unlinkat(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_mkdirat")
int ig_enter_mkdirat(struct trace_event_raw_sys_enter *ctx)
{
	return ig_sc_enter(SC_MKDIRAT, (__s32)ctx->args[0], -1, 0);
}

SEC("tp/syscalls/sys_exit_mkdirat")
int ig_exit_mkdirat(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

// ── mmap/munmap ──

SEC("tp/syscalls/sys_enter_mmap")
int ig_enter_mmap(struct trace_event_raw_sys_enter *ctx)
{
	return ig_sc_enter(SC_MMAP, (__s32)ctx->args[4],
			       (__s64)ctx->args[5], (__s64)ctx->args[1]);
}

SEC("tp/syscalls/sys_exit_mmap")
int ig_exit_mmap(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

SEC("tp/syscalls/sys_enter_munmap")
int ig_enter_munmap(struct trace_event_raw_sys_enter *ctx)
{
	return ig_sc_enter(SC_MUNMAP, -1, -1, (__s64)ctx->args[1]);
}

SEC("tp/syscalls/sys_exit_munmap")
int ig_exit_munmap(struct trace_event_raw_sys_exit *ctx)
{
	return handle_sc_exit(ctx->ret);
}

char LICENSE[] SEC("license") = "GPL";
