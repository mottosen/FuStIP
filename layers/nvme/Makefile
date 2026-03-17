ifdef DEBUG
    Q =
    ERR_REDIRECT =
else
    Q = @
    ERR_REDIRECT = 2>/dev/null
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
	$(error DEV_FILTER is not set (set DEV_FILTER or CONTAINER_FILTER))
endif
endif

	$(Q)mkdir -p "$(PIDS_DIR)"

ifeq ($(MODE),detailed)
	$(Q)echo -e "\nStarting detailed collection.."

	$(Q)$(MAKE) -C bpf standalone

ifdef CONTAINER_FILTER
	$(Q)sudo ./bpf/c/standalone \
		-o "$(RESULTS_DIR)/nvme/detailed.csv" \
		-c $(CONTAINER_FILTER) \
		$(ERR_REDIRECT) 1>&2 & echo $$! > "$(PIDS_DIR)/detailed.pid"
else
	$(Q)sudo ./bpf/c/standalone \
		-o "$(RESULTS_DIR)/nvme/detailed.csv" \
		-f $(DEV_FILTER) \
		$(ERR_REDIRECT) 1>&2 & echo $$! > "$(PIDS_DIR)/detailed.pid"
endif

	$(Q)echo -e "Detailed collection is running!\n"
else
	$(Q)echo -e "\nStarting bpftrace collection.."

	$(Q)sudo $(BPFTRACE) ./bt/trace.bt $(DEV_FILTER) \
		--no-warnings \
		-o "$(RESULTS_DIR)/nvme/trace.out" \
		$(ERR_REDIRECT) 1>&2 & echo $$! > "$(PIDS_DIR)/trace.pid"

	$(Q)echo -e "bpftrace collection is running!\n"
endif

.PHONY: stop-collection
stop-collection:
	$(Q)for pidfile in $(PIDS_DIR)/*.pid; do \
		if [ -f "$$pidfile" ]; then \
			kill $$(cat "$$pidfile") $(ERR_REDIRECT) 1>&2 || true; \
		fi; \
	done
	$(Q)rm -rf "$(PIDS_DIR)"
	@echo "nvme collection stopped"
	$(Q)sleep 2

ifeq ($(MODE),detailed)
	$(Q)if [ -f "$(RESULTS_DIR)/nvme/detailed.csv" ]; then \
		$(MAKE) generate-stats; \
	fi
else
	$(Q)if [ -f "$(RESULTS_DIR)/nvme/trace.out" ]; then \
		$(MAKE) generate-stats; \
	fi
endif

.PHONY: generate-stats
generate-stats: ensure-results-exists
ifeq ($(MODE),detailed)
	$(Q)python "./util/generate_detailed_stats.py" "$(RESULTS_DIR)" $(ERR_REDIRECT) 1>/dev/null
else
	$(Q)python "./util/generate_summary_stats.py" "$(RESULTS_DIR)" $(ERR_REDIRECT) 1>/dev/null
endif
	@echo "nvme stats generated"

.PHONY: visualize
visualize: ensure-results-exists
	$(Q)python "./util/visualize.py" "$(RESULTS_DIR)" $(ERR_REDIRECT) 1>/dev/null
	$(Q)echo -e "nvme visualization generated"
