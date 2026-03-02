ifdef DEBUG
    Q =
    ERR_REDIRECT =
    MAKE_FLAGS =
else
    Q = @
    ERR_REDIRECT = 2>/dev/null 1>&2
    MAKE_FLAGS = --no-print-directory
endif

MAKE := $(MAKE) $(MAKE_FLAGS)

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
	$(Q)echo -e "\nEnsuring results dir exists.."

	$(Q)if [ ! -d "$(RESULTS_DIR)" ]; then \
		echo "Results dir was not found: $(RESULTS_DIR)"; \
		exit 1; \
	fi

	$(Q)mkdir -p "$(RESULTS_DIR)/nvme"

	$(Q)echo -e "Results dir was found or created.\n"

.PHONY: start-collection
start-collection: ensure-results-exists ensure-sudo
ifndef DEV_FILTER
	$(error DEV_FILTER is not set)
endif

	$(Q)mkdir -p "$(PIDS_DIR)"

ifeq ($(MODE),detailed)
	$(Q)echo -e "\nStarting detailed collection.."

	$(Q)$(MAKE) -C bpf standalone

	$(Q)sudo ./bpf/c/standalone \
		-o "$(RESULTS_DIR)/nvme/detailed.csv" \
		-f $(DEV_FILTER) \
		$(ERR_REDIRECT) & echo $$! > "$(PIDS_DIR)/detailed.pid"

	$(Q)echo -e "Detailed collection is running!\n"
else
	$(Q)echo -e "\nStarting bpftrace collection.."

	$(Q)sudo $(BPFTRACE) ./bt/trace.bt $(DEV_FILTER) \
		--no-warnings \
		-o "$(RESULTS_DIR)/nvme/trace.out" \
		$(ERR_REDIRECT) & echo $$! > "$(PIDS_DIR)/trace.pid"

	$(Q)echo -e "bpftrace collection is running!\n"
endif

.PHONY: stop-collection
stop-collection:
	$(Q)echo -e "\nStopping collection.."

	$(Q)for pidfile in $(PIDS_DIR)/*.pid; do \
		if [ -f "$$pidfile" ]; then \
			kill $$(cat "$$pidfile") $(ERR_REDIRECT) || true; \
		fi; \
	done

	$(Q)rm -rf "$(PIDS_DIR)"

	$(Q)echo -e "Collection stopped!\n"

	$(Q)sleep 2

	$(Q)$(MAKE) generate-stats

.PHONY: generate-stats
generate-stats: ensure-results-exists
	$(Q)echo -e "\nGenerating nvme layer stats.."

ifeq ($(MODE),detailed)
	$(Q)python "./util/generate_detailed_stats.py" "$(RESULTS_DIR)"
else
	$(Q)python "./util/generate_summary_stats.py" "$(RESULTS_DIR)"
endif

	$(Q)echo -e "Stats generated!\n"
