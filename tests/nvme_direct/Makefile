ifdef DEBUG
    Q =
    REDIRECT =
else
    Q = @
    REDIRECT = 1>/dev/null 2>&1
    MAKE_FLAGS += --no-print-directory
endif

# If CONTAINER_FILTER is set, force detailed mode
ifdef CONTAINER_FILTER
MODE := detailed
endif

MODE ?= summary
ifneq ($(MODE),summary)
ifneq ($(MODE),detailed)
$(error MODE must be 'summary' or 'detailed' (got '$(MODE)'))
endif
endif

MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# nvme_direct exercises the NVMe layer over io_uring_cmd passthrough, which
# bypasses the block layer — so this suite only profiles the nvme layer.
NVME_DIR = ../../layers/nvme
UTIL_DIR := $(MAKEFILE_DIR)../../util

FIO_OUT = $(RESULTS_DIR)/fio/nvme_direct-fio_out.json
# Self-relative rather than $(ROOT_DIR)-relative: when FuStIP is vendored as a
# submodule the surrounding project exports its own ROOT_DIR, which silently
# resolved this to a nonexistent path and broke every container-mode job.
FIO_COMPOSE ?= $(MAKEFILE_DIR)../../util/container/fio-test/fio-test.yml

# Docker Compose command, inferred from the environment (provided by devbox):
# prefer the v2 plugin (`docker compose`), fall back to the standalone binary
# (`docker-compose`). With the wrong/absent one, `docker` parses the `-f` as a
# root flag → "unknown shorthand flag: 'f'" / exit 125.
DOCKER_COMPOSE := $(shell docker compose version >/dev/null 2>&1 && echo "docker compose" || echo "docker-compose")

VAL_JOBS = val_seqread val_seqwrite val_randread val_randwrite val_randrw val_high_qd
WORK_JOBS = work_index_search work_bulk_insert work_compaction work_query_insert work_scan work_high_qd
STRESS_JOBS = stress_2m stress_5m stress_10m

.NOTPARALLEL:

.PHONY: ensure-sudo
ensure-sudo:
	$(Q)echo -e "\nEnsuring sudo is available.."
	$(Q)sudo -v
	$(Q)echo -e "Done!\n"

# Safety guard: passthrough writes hit the whole namespace from LBA 0, so refuse
# to run against a device with mounted partitions or data signatures. Override a
# stray signature (never a mount) on a genuine scratch device with
# ALLOW_NONEMPTY_DEVICE=1.
.PHONY: ensure-device-free
ensure-device-free:
	$(Q)python $(MAKEFILE_DIR)assert_device_free.py "$(FIO_FILE)"

# Build the fio-test image up front (container mode only) so the per-job
# `docker compose run` does no image-build I/O *inside* the traced window. The
# build is cached; it only does real work when the context changes.
.PHONY: prebuild
prebuild:
ifdef CONTAINER_FILTER
	$(Q)FIO_DIR=$(dir $(FIO_FILE)) TEST_DIR=$(MAKEFILE_DIR) RESULTS_DIR=$(RESULTS_DIR) \
		$(DOCKER_COMPOSE) -f $(FIO_COMPOSE) build $(REDIRECT)
endif

# ── Aggregate targets ──

.PHONY: validate
validate: $(VAL_JOBS)

.PHONY: workload
workload: $(WORK_JOBS)

.PHONY: stress
stress: $(STRESS_JOBS)

.PHONY: all
all: validate workload stress

# ── Per-job pattern ──
# Each target: wait for device quiescence → start collection → run fio →
# stop collection → check results. The quiescence wait (and prebuild prereq)
# keep the previous job's draining I/O and the container build out of the
# capture window, which otherwise pollutes short jobs (seq/rnd, counts).

ifeq ($(MODE),detailed)
    NVME_OUT_FLAG = --nvme-out $(RESULTS_DIR)/nvme/detailed-stats.json
    MODE_FLAG = --mode detailed
else
    NVME_OUT_FLAG = --nvme-out $(RESULTS_DIR)/nvme/trace.out
    MODE_FLAG =
endif

LAYERS ?= nvme

# Variables passed to layer Makefiles
ifdef CONTAINER_FILTER
    LAYER_VARS = CONTAINER_FILTER=$(CONTAINER_FILTER) RESULTS_DIR=$(RESULTS_DIR)
    CONTAINER_FLAG = --container
else
    LAYER_VARS = MODE=$(MODE) RESULTS_DIR=$(RESULTS_DIR)
    CONTAINER_FLAG =
endif

define JOB_TEMPLATE
.PHONY: $(1)
$(1): ensure-device-free ensure-sudo prebuild
	$(Q)echo -e "\n============================================================"
	$(Q)echo -e "  Running: $(1)  [mode=$(MODE)]$(if $(PROFILER_CPUSET),  [collectors pinned to $(PROFILER_CPUSET)],  [collectors unpinned])  (io_uring_cmd / nvme passthrough)"
	$(Q)echo -e "============================================================\n"
	$(Q)bash $(UTIL_DIR)/wait_device_idle.sh "$(if $(DEV_FILTER),$(DEV_FILTER),$(FIO_FILE))" 10 $(REDIRECT) || true
	$(if $(filter nvme,$(LAYERS)),$(Q)$(MAKE) -C $(NVME_DIR) start-collection $(LAYER_VARS) $(REDIRECT))
	$(Q)sleep 5
	$(Q)mkdir -p $(RESULTS_DIR)/fio
ifdef CONTAINER_FILTER
	$(Q)FIO_DIR=$(dir $(FIO_FILE)) TEST_DIR=$(MAKEFILE_DIR) RESULTS_DIR=$(RESULTS_DIR) \
		$(DOCKER_COMPOSE) -f $(FIO_COMPOSE) run --rm --name $(CONTAINER_FILTER) \
		fio-test ./jobs.fio \
		--filename=$(FIO_FILE) --output-format=json \
		--output=$(FIO_OUT) --section=$(1) \
		$(REDIRECT)
else
	$(Q)sudo fio $(MAKEFILE_DIR)jobs.fio --filename=$(FIO_FILE) \
		--output-format=json --output=$(FIO_OUT) \
		--section=$(1)
endif
	$(Q)sleep 5
	$(if $(filter nvme,$(LAYERS)),$(Q)$(MAKE) -C $(NVME_DIR) stop-profiling $(LAYER_VARS) $(REDIRECT))
	$(if $(filter nvme,$(LAYERS)),$(Q)$(MAKE) -C $(NVME_DIR) csv-to-parquet $(LAYER_VARS) $(REDIRECT))
	$(if $(filter nvme,$(LAYERS)),$(Q)$(MAKE) -C $(NVME_DIR) generate-stats $(LAYER_VARS) $(REDIRECT))
	$(Q)sleep 1
	$(Q)python $(MAKEFILE_DIR)check_test.py --job $(1) \
		--fio-json $(FIO_OUT) \
		$(if $(filter nvme,$(LAYERS)),$(NVME_OUT_FLAG)) \
		$(MODE_FLAG) \
		$(CONTAINER_FLAG)
endef

$(foreach job,$(VAL_JOBS) $(WORK_JOBS) $(STRESS_JOBS),$(eval $(call JOB_TEMPLATE,$(job))))
