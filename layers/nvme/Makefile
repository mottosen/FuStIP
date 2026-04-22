ifdef DEBUG
    Q =
    ERR_REDIRECT =
    OUT_REDIRECT =
else
    Q = @
    ERR_REDIRECT = 2>/dev/null
    OUT_REDIRECT = 1>/dev/null
    MAKEFLAGS += --no-print-directory
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

BPFTRACE := $(shell which bpftrace)
PIDS_DIR = /tmp/bpftrace_nvme-pids

INTERVAL ?= 1

.NOTPARALLEL:

.PHONY: ensure-sudo
ensure-sudo:
	$(Q)echo -e "\nEnsuring sudo is available.."

	$(Q)sudo -v

	$(Q)echo -e "Done!\n"

.PHONY: ensure-results-exists
ensure-results-exists:
	$(Q)if [ ! -d "$(RESULTS_DIR)" ]; then \
		echo "Results dir was not found: $(RESULTS_DIR)"; \
		exit 1; \
	fi
	$(Q)mkdir -p "$(RESULTS_DIR)/nvme"

.PHONY: start-collection
start-collection: ensure-results-exists ensure-sudo
ifndef CONTAINER_FILTER
ifndef DEV_FILTER
ifndef COMM_FILTER
	$(error DEV_FILTER or COMM_FILTER is not set (set DEV_FILTER, COMM_FILTER, or CONTAINER_FILTER))
endif
endif
endif

	$(Q)mkdir -p "$(PIDS_DIR)"

ifeq ($(MODE),detailed)
	$(Q)echo -e "\nStarting detailed collection.."

	$(Q)$(MAKE) -C bpf standalone

	$(Q)sudo rm -f "$(RESULTS_DIR)/nvme/detailed.csv" "$(RESULTS_DIR)/nvme/counters.json" $(ERR_REDIRECT) || true
	$(Q)touch "$(RESULTS_DIR)/nvme/detailed.csv" "$(RESULTS_DIR)/nvme/counters.json"
	$(Q)if [ -n "$(DEV_FILTER)" ]; then \
		printf '{"device": "%s"}\n' "$(DEV_FILTER)" > "$(RESULTS_DIR)/nvme/device-info.json"; \
	fi
	$(Q)sudo ./bpf/c/standalone \
		-o "$(RESULTS_DIR)/nvme/detailed.csv" \
		$(if $(DEV_FILTER),-f $(DEV_FILTER)) \
		$(if $(COMM_FILTER),-p $(COMM_FILTER)) \
		$(if $(CONTAINER_FILTER),-c $(CONTAINER_FILTER)) \
		$(ERR_REDIRECT) 1>&2 & echo $$! > "$(PIDS_DIR)/detailed.pid"

	$(Q)echo -e "Detailed collection is running!\n"
else
	$(Q)echo -e "\nStarting bpftrace collection.."

	$(Q)sudo $(BPFTRACE) ./bt/trace.bt "$(if $(DEV_FILTER),$(DEV_FILTER),_)" "$(if $(COMM_FILTER),$(COMM_FILTER),_)" \
		--no-warnings \
		-o "$(RESULTS_DIR)/nvme/trace.out" \
		$(ERR_REDIRECT) 1>&2 & echo $$! > "$(PIDS_DIR)/trace.pid"

	$(Q)echo -e "bpftrace collection is running!\n"
endif

.PHONY: stop-profiling
stop-profiling:
	$(Q)for pidfile in $(PIDS_DIR)/*.pid; do \
		if [ -f "$$pidfile" ]; then \
			pid=$$(cat "$$pidfile"); \
			kill $$pid $(ERR_REDIRECT) 1>&2 || true; \
			i=0; while [ -d "/proc/$$pid" ] && [ $$i -lt 50 ]; do \
				sleep 0.2; i=$$((i+1)); \
			done; \
		fi; \
	done
	$(Q)rm -rf "$(PIDS_DIR)"
	@echo "nvme collection stopped"

.PHONY: csv-to-parquet
csv-to-parquet: ensure-results-exists
ifeq ($(MODE),detailed)
	$(Q)if [ -f "$(RESULTS_DIR)/nvme/detailed.csv" ]; then \
		python "../../util/csv_to_parquet.py" "$(RESULTS_DIR)/nvme/detailed.csv" $(ERR_REDIRECT) $(OUT_REDIRECT) && \
		rm -f "$(RESULTS_DIR)/nvme/detailed.csv"; \
	fi
endif

.PHONY: stop-collection
stop-collection: stop-profiling csv-to-parquet generate-stats

.PHONY: generate-stats
generate-stats: ensure-results-exists
ifeq ($(MODE),detailed)
	$(Q)python "./util/generate_detailed_stats.py" "$(RESULTS_DIR)" $(ERR_REDIRECT) $(OUT_REDIRECT)
else
	$(Q)python "./util/generate_summary_stats.py" "$(RESULTS_DIR)" $(ERR_REDIRECT) $(OUT_REDIRECT)
endif
	@echo "nvme stats generated"

.PHONY: visualize
visualize: ensure-results-exists
	$(Q)if [ -f "$(RESULTS_DIR)/nvme/detailed.csv" ]; then \
		python "../../util/csv_to_parquet.py" "$(RESULTS_DIR)/nvme/detailed.csv" $(ERR_REDIRECT) $(OUT_REDIRECT) && \
		rm -f "$(RESULTS_DIR)/nvme/detailed.csv"; \
	fi
	$(Q)python "./util/visualize.py" "$(RESULTS_DIR)" $(ERR_REDIRECT) $(OUT_REDIRECT)
	$(Q)echo -e "nvme visualization generated"
