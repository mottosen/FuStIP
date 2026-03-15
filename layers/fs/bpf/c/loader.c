// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include "../event.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "standalone.skel.h"

static volatile sig_atomic_t running = 1;
static FILE *output;

static const char *syscall_names[] = {
	[0]  = "read",
	[1]  = "write",
	[2]  = "pread64",
	[3]  = "pwrite64",
	[4]  = "openat",
	[5]  = "close",
	[6]  = "lseek",
	[7]  = "newfstatat",
	[8]  = "newfstat",
	[9]  = "unlinkat",
	[10] = "mkdirat",
	[11] = "mmap",
	[12] = "munmap",
};

static const char *sc_name(__u8 idx)
{
	if (idx < sizeof(syscall_names) / sizeof(syscall_names[0]))
		return syscall_names[idx];
	return "unknown";
}

static void sig_handler(int sig)
{
	running = 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct fs_event *e = data;
	const char *event = e->event_type == 0 ? "enter" : "exit";
	char comm[17] = {};
	memcpy(comm, e->comm, 16);

	// Format: timestamp_ns,event,syscall,bytes,latency_ns,fd,offset,tid,comm
	fprintf(output, "%llu,%s,%s,",
		e->timestamp_ns, event, sc_name(e->syscall));

	// bytes
	if (e->bytes != 0)
		fprintf(output, "%lld,", e->bytes);
	else
		fprintf(output, ",");

	// latency_ns
	if (e->latency_ns > 0)
		fprintf(output, "%llu,", e->latency_ns);
	else
		fprintf(output, ",");

	// fd
	if (e->fd >= 0)
		fprintf(output, "%d,", e->fd);
	else
		fprintf(output, ",");

	// offset
	if (e->offset >= 0)
		fprintf(output, "%lld,", e->offset);
	else
		fprintf(output, ",");

	// tid,comm
	fprintf(output, "%u,%s\n", e->tid, comm);

	return 0;
}

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s -o <output_csv> -f <comm_filter[,comm2,...]>\n", prog);
	exit(1);
}

static int parse_comm_filters(struct standalone_bpf *skel, const char *filter)
{
	char buf[256];
	strncpy(buf, filter, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	int count = 0;
	char *saveptr = NULL;
	char *token = strtok_r(buf, ",", &saveptr);
	while (token && count < 8) {
		strncpy((char *)skel->rodata->comm_filters[count], token, 15);
		count++;
		token = strtok_r(NULL, ",", &saveptr);
	}
	skel->rodata->num_comm_filters = count;
	return count;
}

int main(int argc, char **argv)
{
	char *output_path = NULL;
	char *filter = NULL;
	int opt;

	while ((opt = getopt(argc, argv, "o:f:")) != -1) {
		switch (opt) {
		case 'o':
			output_path = optarg;
			break;
		case 'f':
			filter = optarg;
			break;
		default:
			usage(argv[0]);
		}
	}

	if (!output_path || !filter)
		usage(argv[0]);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	struct standalone_bpf *skel = standalone_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// Set filters in rodata
	parse_comm_filters(skel, filter);

	int err = standalone_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		standalone_bpf__destroy(skel);
		return 1;
	}

	err = standalone_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
		standalone_bpf__destroy(skel);
		return 1;
	}

	output = fopen(output_path, "w");
	if (!output) {
		fprintf(stderr, "Failed to open output file: %s\n", output_path);
		standalone_bpf__destroy(skel);
		return 1;
	}
	fprintf(output, "timestamp_ns,event,syscall,bytes,latency_ns,fd,offset,tid,comm\n");

	struct ring_buffer *rb = ring_buffer__new(
		bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		fclose(output);
		standalone_bpf__destroy(skel);
		return 1;
	}

	fprintf(stderr, "FS layer detailed tracing started (filter: %s)...\n",
		filter);

	while (running) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR)
			break;
		if (err < 0) {
			fprintf(stderr, "Ring buffer poll error: %d\n", err);
			break;
		}
	}

	fprintf(stderr, "Stopping...\n");

	ring_buffer__free(rb);
	fclose(output);
	standalone_bpf__destroy(skel);

	return 0;
}
