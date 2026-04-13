// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include "../event.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "standalone.skel.h"

static volatile sig_atomic_t running = 1;
static FILE *output;
#define MAX_CONTAINER_FILTERS 32
#define MAX_COMM_FILTERS 8

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

static void write_counters(struct standalone_bpf *skel, const char *csv_path)
{
	int fd = bpf_map__fd(skel->maps.event_counters);
	int ncpus = libbpf_num_possible_cpus();
	if (ncpus <= 0)
		return;

	/* Per-event-type counters: enter=0,1  exit=2,3 */
	__u64 values[ncpus];
	__u64 totals[4] = {};

	for (__u32 key = 0; key < 4; key++) {
		memset(values, 0, sizeof(values));
		if (bpf_map_lookup_elem(fd, &key, values) == 0) {
			for (int i = 0; i < ncpus; i++)
				totals[key] += values[i];
		}
	}

	char path[512];
	strncpy(path, csv_path, sizeof(path) - 1);
	path[sizeof(path) - 1] = '\0';
	char *slash = strrchr(path, '/');
	if (slash)
		strcpy(slash + 1, "counters.json");
	else
		strcpy(path, "counters.json");

	FILE *f = fopen(path, "w");
	if (!f)
		return;
	fprintf(f, "{\"enter\": {\"generated\": %llu, \"dropped\": %llu}, "
		   "\"exit\": {\"generated\": %llu, \"dropped\": %llu}}\n",
		totals[0], totals[1], totals[2], totals[3]);
	fclose(f);
	fprintf(stderr, "Counters: enter(gen=%llu drop=%llu) exit(gen=%llu drop=%llu) -> %s\n",
		totals[0], totals[1], totals[2], totals[3], path);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct fs_event *e = data;
	const char *event = e->event_type == 0 ? "enter" : "exit";
	char comm[17] = {};
	memcpy(comm, e->comm, 16);

	// Format: timestamp_ns,mntns_id,event,syscall,bytes,latency_ns,fd,offset,tid,comm,inflight
	fprintf(output, "%llu,%llu,%s,%s,",
		e->timestamp_ns, e->mntns_id, event, sc_name(e->syscall));

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

	// tid,comm,inflight
	fprintf(output, "%u,%s,%d\n", e->tid, comm, e->inflight);

	return 0;
}

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s -o <output_csv> [-f <comm_filter[,comm2,...]>] [-c <container_name[,container2,...]>]\n", prog);
	fprintf(stderr, "  -f (comm) or -c (container) required; both enables OR mode\n");
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
	while (token && count < MAX_COMM_FILTERS) {
		strncpy((char *)skel->rodata->comm_filters[count], token, 15);
		count++;
		token = strtok_r(NULL, ",", &saveptr);
	}
	if (token)
		fprintf(stderr, "Warning: only first %d comm filters are used\n", MAX_COMM_FILTERS);
	skel->rodata->num_comm_filters = count;
	return count;
}

static int parse_container_filters(const char *csv, char out[][128], int max_entries)
{
	char buf[1024];
	strncpy(buf, csv, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	int count = 0;
	char *saveptr = NULL;
	char *token = strtok_r(buf, ",", &saveptr);
	while (token && count < max_entries) {
		while (*token && isspace((unsigned char)*token))
			token++;
		char *end = token + strlen(token);
		while (end > token && isspace((unsigned char)*(end - 1)))
			*--end = '\0';
		if (*token != '\0') {
			strncpy(out[count], token, 127);
			out[count][127] = '\0';
			count++;
		}
		token = strtok_r(NULL, ",", &saveptr);
	}
	if (token)
		fprintf(stderr, "Warning: only first %d containers are used\n", max_entries);
	return count;
}

static int try_resolve_container(struct standalone_bpf *skel,
				 const char *container_name)
{
	char cmd[256];
	snprintf(cmd, sizeof(cmd),
		 "docker inspect --format '{{.State.Pid}}' %s 2>/dev/null",
		 container_name);

	FILE *fp = popen(cmd, "r");
	if (!fp)
		return 0;

	char pid_buf[32] = {};
	if (!fgets(pid_buf, sizeof(pid_buf), fp)) {
		pclose(fp);
		return 0;
	}
	pclose(fp);

	long pid = strtol(pid_buf, NULL, 10);
	if (pid <= 0)
		return 0;

	char ns_path[64];
	snprintf(ns_path, sizeof(ns_path), "/proc/%ld/ns/mnt", pid);

	char link[64] = {};
	ssize_t len = readlink(ns_path, link, sizeof(link) - 1);
	if (len <= 0)
		return 0;
	link[len] = '\0';

	// Parse "mnt:[INODE]"
	char *start = strchr(link, '[');
	char *end = strchr(link, ']');
	if (!start || !end || end <= start)
		return 0;

	start++;
	*end = '\0';
	__u64 mntns_id = strtoull(start, NULL, 10);
	if (mntns_id == 0)
		return 0;

	__u32 val = 1;
	int fd = bpf_map__fd(skel->maps.mntns_filter);
	if (bpf_map_update_elem(fd, &mntns_id, &val, BPF_ANY) != 0) {
		fprintf(stderr, "Failed to update mntns_filter map\n");
		return 0;
	}

	fprintf(stderr, "Resolved container '%s': pid=%ld mntns=%llu\n",
		container_name, pid, mntns_id);
	return 1;
}

int main(int argc, char **argv)
{
	char *output_path = NULL;
	char *filter = NULL;
	char *container_filter = NULL;
	char container_names[MAX_CONTAINER_FILTERS][128] = {};
	int container_count = 0;
	int container_resolved[MAX_CONTAINER_FILTERS] = {};
	int opt;

	while ((opt = getopt(argc, argv, "o:f:c:")) != -1) {
		switch (opt) {
		case 'o':
			output_path = optarg;
			break;
		case 'f':
			filter = optarg;
			break;
		case 'c':
			container_filter = optarg;
			break;
		default:
			usage(argv[0]);
		}
	}

	if (!output_path || (!filter && !container_filter))
		usage(argv[0]);

	if (container_filter) {
		container_count = parse_container_filters(container_filter, container_names, MAX_CONTAINER_FILTERS);
		if (container_count == 0) {
			fprintf(stderr, "Error: no valid container names parsed from -c\n");
			return 1;
		}
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	struct standalone_bpf *skel = standalone_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// Set filters in rodata
	if (filter)
		parse_comm_filters(skel, filter);
	if (container_count > 0)
		skel->rodata->filter_by_mntns = true;
	if (filter && container_count > 0)
		skel->rodata->filter_or_mode = true;

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
	fprintf(output, "timestamp_ns,mntns_id,event,syscall,bytes,latency_ns,fd,offset,tid,comm,inflight\n");

	struct ring_buffer *rb = ring_buffer__new(
		bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		fclose(output);
		standalone_bpf__destroy(skel);
		return 1;
	}

	if (filter && container_count > 0)
		fprintf(stderr, "FS layer detailed tracing started (comm: %s, containers: %s, OR mode)...\n",
			filter, container_filter);
	else if (filter)
		fprintf(stderr, "FS layer detailed tracing started (filter: %s)...\n",
			filter);
	else
		fprintf(stderr, "FS layer detailed tracing started (containers: %s)...\n",
			container_filter);

	// Event loop
	int num_resolved = 0;
	time_t last_attempt = 0;

	while (running) {
		if (container_count > 0 && num_resolved < container_count) {
			time_t now = time(NULL);
			if (now - last_attempt >= 1) {
				for (int i = 0; i < container_count; i++) {
					if (!container_resolved[i] &&
					    try_resolve_container(skel, container_names[i])) {
						container_resolved[i] = 1;
						num_resolved++;
					}
				}
				last_attempt = now;
			}
		}
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
	write_counters(skel, output_path);
	fclose(output);
	standalone_bpf__destroy(skel);

	return 0;
}
