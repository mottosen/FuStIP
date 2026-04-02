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

BLOCK_DIR = ../../layers/block
NVME_DIR = ../../layers/nvme

FIO_OUT = $(RESULTS_DIR)/fio/block_nvme-fio_out.json
FIO_COMPOSE ?= $(ROOT_DIR)/util/container/fio-test/fio-test.yml

VAL_JOBS = val_seqread val_seqwrite val_randread val_randwrite val_randrw val_high_qd
WORK_JOBS = work_index_search work_bulk_insert work_compaction work_query_insert work_scan work_high_qd
STRESS_JOBS = stress_10m
#stress_2m stress_5m 

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
    BLOCK_OUT_FLAG = --block-out $(RESULTS_DIR)/block/detailed-stats.json
    NVME_OUT_FLAG = --nvme-out $(RESULTS_DIR)/nvme/detailed-stats.json
    MODE_FLAG = --mode detailed
else
    BLOCK_OUT_FLAG = --block-out $(RESULTS_DIR)/block/trace.out
    NVME_OUT_FLAG = --nvme-out $(RESULTS_DIR)/nvme/trace.out
    MODE_FLAG =
endif

LAYERS ?= block nvme

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
	$(if $(filter block,$(LAYERS)),$(Q)$(MAKE) -C $(BLOCK_DIR) start-collection $(LAYER_VARS) $(REDIRECT))
	$(if $(filter nvme,$(LAYERS)),$(Q)$(MAKE) -C $(NVME_DIR) start-collection $(LAYER_VARS) $(REDIRECT))
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
	$(Q)( \
		$(if $(filter nvme,$(LAYERS)), $(MAKE) -C $(NVME_DIR) stop-profiling $(LAYER_VARS) $(REDIRECT) &) \
		$(if $(filter block,$(LAYERS)), $(MAKE) -C $(BLOCK_DIR) stop-profiling $(LAYER_VARS) $(REDIRECT) &) \
		wait )
	$(if $(filter nvme,$(LAYERS)),$(Q)$(MAKE) -C $(NVME_DIR) csv-to-parquet $(LAYER_VARS) $(REDIRECT))
	$(if $(filter block,$(LAYERS)),$(Q)$(MAKE) -C $(BLOCK_DIR) csv-to-parquet $(LAYER_VARS) $(REDIRECT))
	$(if $(filter nvme,$(LAYERS)),$(Q)$(MAKE) -C $(NVME_DIR) generate-stats $(LAYER_VARS) $(REDIRECT))
	$(if $(filter block,$(LAYERS)),$(Q)$(MAKE) -C $(BLOCK_DIR) generate-stats $(LAYER_VARS) $(REDIRECT))
	$(Q)sleep 1
	$(Q)python $(MAKEFILE_DIR)check_test.py --job $(1) \
		--fio-json $(FIO_OUT) \
		$(if $(filter block,$(LAYERS)),$(BLOCK_OUT_FLAG)) \
		$(if $(filter nvme,$(LAYERS)),$(NVME_OUT_FLAG)) \
		$(MODE_FLAG) \
		$(CONTAINER_FLAG)
endef

$(foreach job,$(VAL_JOBS) $(WORK_JOBS) $(STRESS_JOBS),$(eval $(call JOB_TEMPLATE,$(job))))
