// SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include "../event.h"
#include "standalone.skel.h"
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t running = 1;
static FILE *output;

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

static int handle_event(void *ctx, void *data, size_t data_sz) {
  const struct nvme_event *e = data;

  if (e->latency_ns > 0)
    fprintf(output, "%llu,%s,%s,%u,%llu,%llu,0x%llx\n", e->timestamp_ns,
            event_name(e->event_type), op_name(e->op), e->bytes, e->latency_ns,
            e->sector, e->rq);
  else
    fprintf(output, "%llu,%s,%s,%u,,%llu,0x%llx\n", e->timestamp_ns,
            event_name(e->event_type), op_name(e->op), e->bytes, e->sector,
            e->rq);

  return 0;
}

static void usage(const char *prog) {
  fprintf(stderr, "Usage: %s -o <output_csv> -f <dev_filter>\n", prog);
  exit(1);
}

int main(int argc, char **argv) {
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

  skel->rodata->has_dev_filter = true;
  strncpy((char *)skel->rodata->dev_filter, filter,
          sizeof(skel->rodata->dev_filter) - 1);

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
  fprintf(output, "timestamp_ns,event,op,bytes,latency_ns,sector,rq\n");

  struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
                                            handle_event, NULL, NULL);
  if (!rb) {
    fprintf(stderr, "Failed to create ring buffer\n");
    fclose(output);
    standalone_bpf__destroy(skel);
    return 1;
  }

  fprintf(stderr, "NVMe layer detailed tracing started (filter: %s)...\n",
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
