ifdef DEBUG
    Q =
    ERR_REDIRECT =
    OUT_REDIRECT =
    VERBOSE_FLAG = -v
else
    Q = @
    ERR_REDIRECT = 2>/dev/null
    OUT_REDIRECT = 1>/dev/null
    VERBOSE_FLAG =
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
ifndef PID_FILTER
	$(error no filter set (set DEV_FILTER, COMM_FILTER, PID_FILTER, or CONTAINER_FILTER))
endif
endif
endif
endif

	$(Q)mkdir -p "$(PIDS_DIR)"

# Device fingerprint (nvme-cli + sysfs) — independent of mode; captured whenever the
# nvme layer runs so post-processing always has logical-block size / capacity, even
# without -d. With no DEV_FILTER, collect_device_info enumerates all NVMe namespaces.
	$(Q)python "./util/collect_device_info.py" "$(RESULTS_DIR)" "$(DEV_FILTER)" $(ERR_REDIRECT) || true

ifeq ($(MODE),detailed)
	$(Q)echo -e "\nStarting detailed collection.."

	$(Q)$(MAKE) -C bpf standalone

	$(Q)sudo rm -f "$(RESULTS_DIR)/nvme/detailed.csv" "$(RESULTS_DIR)/nvme/counters.json" $(ERR_REDIRECT) || true
	$(Q)touch "$(RESULTS_DIR)/nvme/detailed.csv" "$(RESULTS_DIR)/nvme/counters.json"
	$(Q)sudo ./bpf/c/standalone \
		-o "$(RESULTS_DIR)/nvme/detailed.csv" \
		$(if $(DEV_FILTER),-f $(DEV_FILTER)) \
		$(if $(COMM_FILTER),-p $(COMM_FILTER)) \
		$(if $(PID_FILTER),-P $(PID_FILTER)) \
		$(if $(CONTAINER_FILTER),-c $(CONTAINER_FILTER)) \
		$(VERBOSE_FLAG) \
		$(ERR_REDIRECT) 1>&2 & echo $$! > "$(PIDS_DIR)/detailed.pid"

	$(Q)echo -e "Detailed collection is running!\n"
else
	$(Q)echo -e "\nStarting bpftrace collection.."

# Remove any stale output first so the readiness poll below can't match a marker
# left by a previous run (bpftrace also truncates on open, but this closes the race).
	$(Q)sudo rm -f "$(RESULTS_DIR)/nvme/trace.out" $(ERR_REDIRECT) || true

	$(Q)sudo $(BPFTRACE) ./bt/trace.bt "$(if $(DEV_FILTER),$(DEV_FILTER),_)" "$(if $(COMM_FILTER),$(COMM_FILTER),_)" \
		$$(python -c "import json; d=json.load(open('$(RESULTS_DIR)/nvme/device-info.json')); dev='$(DEV_FILTER)'.split(',')[0]; print(d.get(dev,{}).get('nsze_lbas',0))" 2>/dev/null || echo 0) \
		$$(echo '$(PID_FILTER)' | tr ',' ' ') \
		--no-warnings \
		-o "$(RESULTS_DIR)/nvme/trace.out" \
		$(ERR_REDIRECT) 1>&2 & echo $$! > "$(PIDS_DIR)/trace.pid"

# Block until bpftrace has attached every probe: its BEGIN block prints the marker
# below to trace.out only after attach completes. Waiting for it (instead of a blind
# sleep in the caller) prevents losing the head of the workload to slow/variable probe
# attach. Bail out if bpftrace dies first, or after a 10s timeout.
	$(Q)pid=$$(cat "$(PIDS_DIR)/trace.pid"); i=0; \
		until sudo grep -q "bpftrace - NVMe Layer" "$(RESULTS_DIR)/nvme/trace.out" 2>/dev/null; do \
			if [ ! -d "/proc/$$pid" ]; then echo "bpftrace exited before becoming ready" >&2; break; fi; \
			i=$$((i+1)); if [ $$i -ge 100 ]; then echo "timed out waiting for bpftrace attach" >&2; break; fi; \
			sleep 0.1; \
		done

	$(Q)echo -e "bpftrace collection is running!\n"
endif

.PHONY: stop-profiling
stop-profiling: ensure-sudo
# The pidfile holds the backgrounded `sudo` wrapper's PID, not the loader's. The
# loader runs as root (sudo's child), so signal it via -P as root: SIGTERM first so
# it flushes counters and closes detailed.csv cleanly, wait for exit, then SIGKILL as
# a backstop and reap the wrapper. A plain unprivileged `kill` of the wrapper PID is
# EPERM (root process) and orphans the loader, which keeps its since-unlinked CSV
# open and silently eats disk until reboot.
	$(Q)for pidfile in $(PIDS_DIR)/*.pid; do \
		if [ -f "$$pidfile" ]; then \
			pid=$$(cat "$$pidfile"); \
			sudo pkill -TERM -P $$pid $(ERR_REDIRECT) 1>&2 || true; \
			i=0; while sudo pgrep -P $$pid >/dev/null 2>&1 && [ $$i -lt 50 ]; do \
				sleep 0.2; i=$$((i+1)); \
			done; \
			sudo pkill -KILL -P $$pid $(ERR_REDIRECT) 1>&2 || true; \
			sudo kill $$pid $(ERR_REDIRECT) 1>&2 || true; \
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
