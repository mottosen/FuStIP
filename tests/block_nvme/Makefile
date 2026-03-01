ifdef DEBUG
    Q =
    REDIRECT =
    MAKE_FLAGS =
else
    Q = @
    REDIRECT = 1>/dev/null 2>&1
    MAKE_FLAGS = --no-print-directory
endif

MAKE := $(MAKE) $(MAKE_FLAGS)

BLOCK_DIR = ../../layers/block
NVME_DIR = ../../layers/nvme

FIO_OUT = block_nvme-fio_out.json

VAL_JOBS = val_seqread val_seqwrite val_randread val_randwrite val_randrw
WORK_JOBS = work_index_search work_bulk_insert work_compaction work_query_insert work_scan work_high_qd

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

.PHONY: all
all: validate workload

.PHONY: reset-results
reset-results:
ifndef RESULTS_DIR
	$(error RESULTS_DIR is not set)
endif

	$(Q)echo -e "Cleaning experiment results.."
	$(Q)rm -rf $(RESULTS_DIR)/*

	$(Q)echo -e "✓ All cleaned up!\n"

# ── Per-job pattern ──
# Each target: start collection → run fio → stop collection → check results

define JOB_TEMPLATE
.PHONY: $(1)
$(1): ensure-sudo
	$(Q)echo -e "\n============================================================"
	$(Q)echo -e "  Running: $(1)"
	$(Q)echo -e "============================================================\n"
	$(Q)$(MAKE) reset-results
	$(Q)$(MAKE) -C $(BLOCK_DIR) start-collection RESULTS_DIR=$(RESULTS_DIR) $(REDIRECT)
	$(Q)$(MAKE) -C $(NVME_DIR) start-collection RESULTS_DIR=$(RESULTS_DIR) $(REDIRECT)
	$(Q)sleep 5
	$(Q)sudo fio ./jobs.fio --filename=$(FIO_FILE) \
		--output-format=json --output=$(FIO_OUT) \
		--section=$(1)
	$(Q)sleep 1
	$(Q)$(MAKE) -C $(NVME_DIR) stop-collection $(REDIRECT)
	$(Q)$(MAKE) -C $(BLOCK_DIR) stop-collection $(REDIRECT)
	$(Q)sleep 1
	$(Q)python check_test.py --job $(1) \
		--fio-json $(FIO_OUT) \
		--block-out $(RESULTS_DIR)/block/trace.out \
		--nvme-out $(RESULTS_DIR)/nvme/trace.out
endef

$(foreach job,$(VAL_JOBS) $(WORK_JOBS),$(eval $(call JOB_TEMPLATE,$(job))))
