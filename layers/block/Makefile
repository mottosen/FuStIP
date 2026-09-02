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
PIDS_DIR = /tmp/bpftrace_block-pids
# Pin the collection process to the cores the caller reserved for profiling, if any.
#
# The consumer is single-threaded, and a single thread whose SMT sibling is busy runs at
# 1.19 M events/s against 2.57 M/s idle — measured. On a host whose CPUs are all allocated
# to the workload it therefore loses events steadily once the workload generates more than
# ~1.2 M/s, and it does so silently: the run completes and the CSV looks normal. Giving it
# another *logical* CPU fixes nothing (1.18 M/s); only freeing the SIBLING does. So
# PROFILER_CPUSET must name WHOLE physical cores, both siblings of each, excluded from
# every other cpuset.
#
# Empty or unset = no pinning, which is the right default: on an unloaded machine there is
# no sibling to lose to. taskset goes before sudo deliberately — affinity is inherited
# across exec, so this needs no privileges of its own.
TASKSET = $(if $(PROFILER_CPUSET),taskset -c $(PROFILER_CPUSET),)
# Refuse an impossible cpuset at PARSE time, before anything is launched.
#
# Without this the failure is silent and looks like success: taskset would exit
# "Invalid argument", the backgrounded loader would never start, start-collection
# would still return 0, and the run would produce an empty capture. That is the
# exact failure class this pinning exists to remove, so it must not be reachable
# through a typo. Parse-time (not recipe-time) so it also fires under `make -n`.
ifneq ($(PROFILER_CPUSET),)
ifneq ($(shell taskset -c $(PROFILER_CPUSET) true >/dev/null 2>&1; echo $$?),0)
$(error PROFILER_CPUSET="$(PROFILER_CPUSET)" is not settable on this machine \
        (taskset rejected it). Give a CPU list this host actually has, or unset \
        it to run unpinned.)
endif
endif

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
	$(Q)mkdir -p "$(RESULTS_DIR)/block"

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

ifeq ($(MODE),detailed)
	$(Q)echo -e "\nStarting detailed collection.."

	$(Q)$(MAKE) -C bpf standalone

	$(Q)sudo rm -f "$(RESULTS_DIR)/block/detailed.csv" "$(RESULTS_DIR)/block/counters.json" $(ERR_REDIRECT) || true
	$(Q)touch "$(RESULTS_DIR)/block/detailed.csv" "$(RESULTS_DIR)/block/counters.json"
	$(Q)$(TASKSET) sudo ./bpf/c/standalone \
		-o "$(RESULTS_DIR)/block/detailed.csv" \
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
	$(Q)sudo rm -f "$(RESULTS_DIR)/block/trace.out" $(ERR_REDIRECT) || true

	$(Q)$(TASKSET) sudo $(BPFTRACE) ./bt/trace.bt "$(if $(DEV_FILTER),$(DEV_FILTER),_)" "$(if $(COMM_FILTER),$(COMM_FILTER),_)" $$(echo '$(PID_FILTER)' | tr ',' ' ') \
		--no-warnings \
		-o "$(RESULTS_DIR)/block/trace.out" \
		$(ERR_REDIRECT) 1>&2 & echo $$! > "$(PIDS_DIR)/trace.pid"

# Block until bpftrace has attached every probe: its BEGIN block prints the marker
# below to trace.out only after attach completes. Waiting for it (instead of a blind
# sleep in the caller) prevents losing the head of the workload to slow/variable probe
# attach. Bail out if bpftrace dies first, or after a 10s timeout.
	$(Q)pid=$$(cat "$(PIDS_DIR)/trace.pid"); i=0; \
		until sudo grep -q "bpftrace - Block Layer" "$(RESULTS_DIR)/block/trace.out" 2>/dev/null; do \
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
	@echo "block collection stopped"

.PHONY: csv-to-parquet
csv-to-parquet: ensure-results-exists
ifeq ($(MODE),detailed)
	$(Q)if [ -f "$(RESULTS_DIR)/block/detailed.csv" ]; then \
		python "../../util/csv_to_parquet.py" "$(RESULTS_DIR)/block/detailed.csv" $(ERR_REDIRECT) $(OUT_REDIRECT) && \
		rm -f "$(RESULTS_DIR)/block/detailed.csv"; \
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
	@echo "block stats generated"

.PHONY: visualize
visualize: ensure-results-exists
	$(Q)if [ -f "$(RESULTS_DIR)/block/detailed.csv" ]; then \
		python "../../util/csv_to_parquet.py" "$(RESULTS_DIR)/block/detailed.csv" $(ERR_REDIRECT) $(OUT_REDIRECT) && \
		rm -f "$(RESULTS_DIR)/block/detailed.csv"; \
	fi
	$(Q)python "./util/visualize.py" "$(RESULTS_DIR)" $(ERR_REDIRECT) $(OUT_REDIRECT)
	$(Q)echo -e "block visualization generated"
