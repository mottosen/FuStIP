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
// 4 MB fully-buffered stdio buffer for the CSV. Collapses per-event writes into
// large write() syscalls so the single-threaded ring-buffer consumer drains fast
// enough to avoid reserve drops under bursty, high-queue-depth workloads.
static char output_buf[1 << 22];
#define MAX_CONTAINER_FILTERS 32
#define MAX_DEV_FILTERS 8
#define MAX_COMM_FILTERS 8
#define MAX_PID_FILTERS 8

static const char *op_name(__u8 op)
{
	switch (op) {
	case 0: return "read";
	case 1: return "write";
	case 2: return "flush";
	case 3: return "discard";
	case 9: return "write_zeros";
	default: return "unknown";
	}
}

static const char *event_name(__u8 type)
{
	switch (type) {
	case 0: return "insert";
	case 1: return "issue";
	case 2: return "complete";
	default: return "unknown";
	}
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

	/* Per-event-type counters: insert=0,1  issue=2,3  complete=4,5 */
	__u64 values[ncpus];
	__u64 totals[6] = {};

	for (__u32 key = 0; key < 6; key++) {
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

	/* Untracked completions (per disk+op): completions whose request was never
	 * tracked at issue — excluded by the device/proc/container filter, or an
	 * issue-probe miss. Build a JSON object from the hash map. */
	struct untracked_key {
		char disk_name[32];
		__u8 op;
	};
	char untracked_json[4096];
	size_t uoff = 0;
	untracked_json[uoff++] = '{';
	__u64 untracked_total = 0;
	int ufd = bpf_map__fd(skel->maps.untracked_completes);
	if (ufd >= 0) {
		struct untracked_key key, next_key;
		void *prev = NULL;
		int first = 1;
		while (bpf_map_get_next_key(ufd, prev, &next_key) == 0) {
			__u64 uval = 0;
			if (bpf_map_lookup_elem(ufd, &next_key, &uval) == 0 && uval > 0) {
				char disk[33] = {};
				memcpy(disk, next_key.disk_name, 32);
				untracked_total += uval;
				if (uoff < sizeof(untracked_json))
					uoff += snprintf(untracked_json + uoff,
							 sizeof(untracked_json) - uoff,
							 "%s\"%s, %s\": %llu", first ? "" : ", ",
							 disk, op_name(next_key.op), uval);
				first = 0;
			}
			key = next_key;
			prev = &key;
		}
	}
	if (uoff < sizeof(untracked_json))
		snprintf(untracked_json + uoff, sizeof(untracked_json) - uoff, "}");
	else
		strcpy(untracked_json + sizeof(untracked_json) - 2, "}");

	FILE *f = fopen(path, "w");
	if (!f)
		return;
	fprintf(f, "{\"insert\": {\"generated\": %llu, \"dropped\": %llu}, "
		   "\"issue\": {\"generated\": %llu, \"dropped\": %llu}, "
		   "\"complete\": {\"generated\": %llu, \"dropped\": %llu}, "
		   "\"untracked\": %s}\n",
		totals[0], totals[1], totals[2], totals[3],
		totals[4], totals[5], untracked_json);
	fclose(f);
	fprintf(stderr, "Counters: insert(gen=%llu drop=%llu) issue(gen=%llu drop=%llu) "
		"complete(gen=%llu drop=%llu) untracked=%llu -> %s\n",
		totals[0], totals[1], totals[2], totals[3],
		totals[4], totals[5], untracked_total, path);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct block_event *e = data;
	char comm[17] = {};
	memcpy(comm, e->comm, 16);

	// Build the CSV line in memory and emit with a single fwrite (no per-call
	// FILE lock); paired with the large setvbuf this keeps the consumer ahead
	// of the ring buffer under high event rates.
	char line[256];
	int n;
	if (e->latency_ns > 0)
		n = snprintf(line, sizeof(line),
			     "%llu,%llu,%s,%s,%u,%llu,%llu,0x%llx,%u,%s,%d,%d\n",
			     e->timestamp_ns, e->mntns_id,
			     event_name(e->event_type),
			     op_name(e->op), e->bytes, e->latency_ns,
			     e->sector, e->rq, e->tid, comm,
			     e->q_inflight, e->d_inflight);
	else
		n = snprintf(line, sizeof(line),
			     "%llu,%llu,%s,%s,%u,,%llu,0x%llx,%u,%s,%d,%d\n",
			     e->timestamp_ns, e->mntns_id,
			     event_name(e->event_type),
			     op_name(e->op), e->bytes,
			     e->sector, e->rq, e->tid, comm,
			     e->q_inflight, e->d_inflight);

	// snprintf returns the would-be length; clamp so a hypothetical overlong
	// line can never make fwrite read past the buffer (free: just a compare).
	if (n > (int)sizeof(line))
		n = sizeof(line);
	fwrite(line, 1, n, output);
	return 0;
}

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s -o <output_csv> [-c <container[,...]>] [-f <dev_filter[,...]>] "
		"[-p <comm_filter[,...]>] [-P <pid_filter[,...]>]\n", prog);
	fprintf(stderr, "  Filter hierarchy (nested AND): -c container > -f device > {-p comm, -P pid}.\n");
	fprintf(stderr, "  comm and pid are unioned; at least one filter required.\n");
	exit(1);
}

static int parse_dev_filters(struct standalone_bpf *skel, const char *filter)
{
	char buf[256];
	strncpy(buf, filter, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	int count = 0;
	char *saveptr = NULL;
	char *token = strtok_r(buf, ",", &saveptr);
	while (token && count < MAX_DEV_FILTERS) {
		strncpy((char *)skel->rodata->dev_filters[count], token, 31);
		count++;
		token = strtok_r(NULL, ",", &saveptr);
	}
	if (token)
		fprintf(stderr, "Warning: only first %d device filters are used\n", MAX_DEV_FILTERS);
	skel->rodata->num_dev_filters = count;
	return count;
}

static int parse_pid_filters(struct standalone_bpf *skel, const char *filter)
{
	char buf[256];
	strncpy(buf, filter, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	int count = 0;
	char *saveptr = NULL;
	char *token = strtok_r(buf, ",", &saveptr);
	while (token && count < MAX_PID_FILTERS) {
		skel->rodata->pid_filters[count] = (__u32)strtoul(token, NULL, 10);
		count++;
		token = strtok_r(NULL, ",", &saveptr);
	}
	if (token)
		fprintf(stderr, "Warning: only first %d pid filters are used\n", MAX_PID_FILTERS);
	skel->rodata->num_pid_filters = count;
	return count;
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
		 "docker inspect --format '{{.State.Pid}}' %.200s 2>/dev/null",
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
	char *dev_filter = NULL;
	char *comm_filter = NULL;
	char *pid_filter = NULL;
	char *container_filter = NULL;
	char container_names[MAX_CONTAINER_FILTERS][128] = {};
	int container_count = 0;
	int container_resolved[MAX_CONTAINER_FILTERS] = {};
	int opt;
	int verbose = 0;

	while ((opt = getopt(argc, argv, "o:f:p:P:c:v")) != -1) {
		switch (opt) {
		case 'o':
			output_path = optarg;
			break;
		case 'f':
			dev_filter = optarg;
			break;
		case 'p':
			comm_filter = optarg;
			break;
		case 'P':
			pid_filter = optarg;
			break;
		case 'c':
			container_filter = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage(argv[0]);
		}
	}

	if (!output_path || (!dev_filter && !comm_filter && !pid_filter && !container_filter))
		usage(argv[0]);

	if (container_filter) {
		container_count = parse_container_filters(container_filter, container_names, MAX_CONTAINER_FILTERS);
		if (container_count == 0) {
			fprintf(stderr, "Error: no valid container names parsed from -c\n");
			return 1;
		}
	}

	// Set up signal handling
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// Open and load BPF skeleton
	struct standalone_bpf *skel = standalone_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// Set filters in rodata
	if (dev_filter)
		parse_dev_filters(skel, dev_filter);
	if (comm_filter)
		parse_comm_filters(skel, comm_filter);
	if (pid_filter)
		parse_pid_filters(skel, pid_filter);
	if (container_count > 0)
		skel->rodata->filter_by_mntns = true;

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

	// Open output file and write CSV header
	output = fopen(output_path, "w");
	if (!output) {
		fprintf(stderr, "Failed to open output file: %s\n", output_path);
		standalone_bpf__destroy(skel);
		return 1;
	}
	setvbuf(output, output_buf, _IOFBF, sizeof(output_buf));
	fprintf(output, "timestamp_ns,mntns_id,event,op,bytes,latency_ns,sector,rq,tid,comm,q_inflight,d_inflight\n");

	// Set up ring buffer
	struct ring_buffer *rb = ring_buffer__new(
		bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		fclose(output);
		standalone_bpf__destroy(skel);
		return 1;
	}

	// Past setup: silence the loader's informational runtime logs (tracing-started
	// banner, container resolution, stop/counters) so they don't reach the terminal
	// in normal runs. Done by reopening our own stderr — which a backgrounded sudo
	// can't reconnect to the tty. The Makefile passes -v only in DEBUG mode; setup
	// and attach errors above still surface.
	if (!verbose && freopen("/dev/null", "w", stderr) == NULL) {
		// best-effort: if the redirect fails, informational logs may still appear
	}

	fprintf(stderr, "Block layer detailed tracing started (container: %s, dev: %s, comm: %s, pid: %s)...\n",
		container_filter ? container_filter : "none",
		dev_filter ? dev_filter : "none",
		comm_filter ? comm_filter : "none",
		pid_filter ? pid_filter : "none");

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

	// Cleanup
	ring_buffer__free(rb);
	write_counters(skel, output_path);
	fclose(output);
	standalone_bpf__destroy(skel);

	return 0;
}
