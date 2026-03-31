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

FS_DIR = ../../layers/fs
SYSSTAT_DIR = ../../layers/sysstat

FIO_OUT = $(RESULTS_DIR)/fio/fs-fio_out.json
FIO_COMPOSE ?= $(ROOT_DIR)/util/container/fio-test/fio-test.yml

VAL_JOBS = val_seqread val_seqwrite val_randread val_randwrite val_randrw
WORK_JOBS = work_index_search work_bulk_insert work_compaction work_query_insert work_scan work_high_qd
STRESS_JOBS = stress_2m stress_5m stress_10m

.NOTPARALLEL:

.PHONY: ensure-sudo
ensure-sudo:
	$(Q)echo -e "\nEnsuring sudo is available.."
	$(Q)sudo -v
	$(Q)echo -e "Done!\n"

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
# Each target: start collection → run fio → stop collection → check results

ifeq ($(MODE),detailed)
    FS_OUT_FLAG = --fs-out $(RESULTS_DIR)/fs/detailed-stats.json
    MODE_FLAG = --mode detailed
else
    FS_OUT_FLAG = --fs-out $(RESULTS_DIR)/fs/trace.out
    MODE_FLAG =
endif

LAYERS ?= fs sysstat

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
$(1): ensure-sudo
	$(Q)echo -e "\n============================================================"
	$(Q)echo -e "  Running: $(1)  [mode=$(MODE)]"
	$(Q)echo -e "============================================================\n"
	$(if $(filter fs,$(LAYERS)),$(Q)$(MAKE) -C $(FS_DIR) start-collection $(LAYER_VARS) $(REDIRECT))
	$(if $(filter sysstat,$(LAYERS)),$(Q)$(MAKE) -C $(SYSSTAT_DIR) start-collection $(LAYER_VARS) $(REDIRECT))
	$(Q)sleep 5
	$(Q)mkdir -p $(RESULTS_DIR)/fio
ifdef CONTAINER_FILTER
	$(Q)FIO_DIR=$(dir $(FIO_FILE)) TEST_DIR=$(MAKEFILE_DIR) RESULTS_DIR=$(RESULTS_DIR) \
		docker compose -f $(FIO_COMPOSE) run --rm --build --name $(CONTAINER_FILTER) \
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
	$(if $(filter sysstat,$(LAYERS)),$(Q)$(MAKE) -C $(SYSSTAT_DIR) stop-collection $(LAYER_VARS) $(REDIRECT))
	$(if $(filter fs,$(LAYERS)),$(Q)$(MAKE) -C $(FS_DIR) stop-collection $(LAYER_VARS) $(REDIRECT))
	$(Q)sleep 1
	$(Q)python $(MAKEFILE_DIR)check_test.py --job $(1) \
		--fio-json $(FIO_OUT) \
		$(if $(filter fs,$(LAYERS)),$(FS_OUT_FLAG)) \
		$(MODE_FLAG) \
		$(CONTAINER_FLAG)
endef

$(foreach job,$(VAL_JOBS) $(WORK_JOBS) $(STRESS_JOBS),$(eval $(call JOB_TEMPLATE,$(job))))
