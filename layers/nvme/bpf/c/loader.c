// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include "../event.h"
#include "standalone.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>

static volatile sig_atomic_t running = 1;
static FILE *output;
#define MAX_CONTAINER_FILTERS 32
#define MAX_DEV_FILTERS 8
#define MAX_COMM_FILTERS 8

static const char *op_name(__u8 op) {
  switch (op) {
  case 0:
    return "read";
  case 1:
    return "write";
  case 2:
    return "flush";
  case 3:
    return "discard";
  case 9:
    return "write_zeros";
  default:
    return "unknown";
  }
}

static const char *event_name(__u8 type) {
  switch (type) {
  case 0:
    return "setup";
  case 1:
    return "complete";
  default:
    return "unknown";
  }
}

static void sig_handler(int sig) { running = 0; }

static void write_counters(struct standalone_bpf *skel, const char *csv_path) {
  int fd = bpf_map__fd(skel->maps.event_counters);
  int ncpus = libbpf_num_possible_cpus();
  if (ncpus <= 0)
    return;

  /* Per-event-type counters: setup=0,1  complete=2,3 */
  __u64 values[ncpus];
  __u64 totals[4] = {};

  for (__u32 key = 0; key < 4; key++) {
    memset(values, 0, sizeof(values));
    if (bpf_map_lookup_elem(fd, &key, values) == 0) {
      for (int i = 0; i < ncpus; i++)
        totals[key] += values[i];
    }
  }

  /* Derive counters.json path from csv_path (same directory) */
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
  fprintf(f, "{\"setup\": {\"generated\": %llu, \"dropped\": %llu}, "
             "\"complete\": {\"generated\": %llu, \"dropped\": %llu}}\n",
          totals[0], totals[1], totals[2], totals[3]);
  fclose(f);
  fprintf(stderr, "Counters: setup(gen=%llu drop=%llu) complete(gen=%llu drop=%llu) -> %s\n",
          totals[0], totals[1], totals[2], totals[3], path);
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
  const struct nvme_event *e = data;
  char comm[17] = {};
  memcpy(comm, e->comm, 16);
  char disk_name[33] = {};
  memcpy(disk_name, e->disk_name, 32);

  if (e->latency_ns > 0)
    fprintf(output, "%llu,%llu,%s,%s,%u,%llu,%llu,0x%llx,%s,%d,%s\n", e->timestamp_ns,
            e->mntns_id, event_name(e->event_type), op_name(e->op), e->bytes, e->latency_ns,
            e->sector, e->rq, comm, e->inflight, disk_name);
  else
    fprintf(output, "%llu,%llu,%s,%s,%u,,%llu,0x%llx,%s,%d,%s\n", e->timestamp_ns,
            e->mntns_id, event_name(e->event_type), op_name(e->op), e->bytes, e->sector,
            e->rq, comm, e->inflight, disk_name);

  return 0;
}

static int parse_dev_filters(struct standalone_bpf *skel, const char *filter) {
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

static int parse_comm_filters(struct standalone_bpf *skel, const char *filter) {
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

static int parse_container_filters(const char *csv, char out[][128], int max_entries) {
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

static void usage(const char *prog) {
  fprintf(stderr,
          "Usage: %s -o <output_csv> [-f <dev_filter[,dev2,...]>] [-p <comm_filter[,comm2,...]>] [-c <container_name[,container2,...]>]\n",
          prog);
  fprintf(stderr, "  -f (device), -p (comm), or -c (container); at least one required\n");
  exit(1);
}

static int try_resolve_container(struct standalone_bpf *skel,
                                 const char *container_name) {
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

int main(int argc, char **argv) {
  char *output_path = NULL;
  char *dev_filter = NULL;
  char *comm_filter = NULL;
  char *container_filter = NULL;
  char container_names[MAX_CONTAINER_FILTERS][128] = {};
  int container_count = 0;
  int container_resolved[MAX_CONTAINER_FILTERS] = {};
  int opt;

  while ((opt = getopt(argc, argv, "o:f:p:c:")) != -1) {
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
    case 'c':
      container_filter = optarg;
      break;
    default:
      usage(argv[0]);
    }
  }

  if (!output_path || (!dev_filter && !comm_filter && !container_filter))
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

  if (dev_filter)
    parse_dev_filters(skel, dev_filter);
  if (comm_filter)
    parse_comm_filters(skel, comm_filter);
  if (container_count > 0)
    skel->rodata->filter_by_mntns = true;
  if ((dev_filter || comm_filter) && container_count > 0)
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
  fprintf(output,
          "timestamp_ns,mntns_id,event,op,bytes,latency_ns,sector,rq,comm,inflight,disk_name\n");

  struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                                            handle_event, NULL, NULL);
  if (!rb) {
    fprintf(stderr, "Failed to create ring buffer\n");
    fclose(output);
    standalone_bpf__destroy(skel);
    return 1;
  }

  if ((dev_filter || comm_filter) && container_count > 0)
    fprintf(stderr, "NVMe layer detailed tracing started (dev: %s, comm: %s, containers: %s, OR mode)...\n",
            dev_filter ? dev_filter : "none",
            comm_filter ? comm_filter : "none",
            container_filter);
  else if (dev_filter || comm_filter)
    fprintf(stderr, "NVMe layer detailed tracing started (dev: %s, comm: %s)...\n",
            dev_filter ? dev_filter : "none",
            comm_filter ? comm_filter : "none");
  else
    fprintf(stderr,
            "NVMe layer detailed tracing started (containers: %s)...\n",
            container_filter);

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
