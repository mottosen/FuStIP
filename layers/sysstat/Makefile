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

PIDSTAT := $(shell which pidstat)
PIDS_DIR = /tmp/sysstat-pids

export TZ := UTC
export LC_ALL := C

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
	$(Q)mkdir -p "$(RESULTS_DIR)/sysstat"
	$(Q)rm -f "$(RESULTS_DIR)/sysstat/container_map.json"

.PHONY: start-collection
start-collection: ensure-results-exists ensure-sudo
	$(Q)echo -e "\nStarting sysstat collection.."

	$(Q)mkdir -p "$(PIDS_DIR)"

	$(Q)sudo -E $(PIDSTAT) -turd $(INTERVAL) \
		> "$(RESULTS_DIR)/sysstat/pidstat.out" \
		$(ERR_REDIRECT) & echo $$! > "$(PIDS_DIR)/pidstat.pid"

	$(Q)echo -e "sysstat collection is running!\n"

.PHONY: stop-profiling
stop-profiling: ensure-sudo
# The pidfile holds the backgrounded `sudo` wrapper's PID, not pidstat's. pidstat runs
# as root (sudo's child), so signal it via -P as root: SIGTERM first so it flushes and
# closes pidstat.out cleanly, wait for exit, then SIGKILL as a backstop and reap the
# wrapper. A plain unprivileged `kill` of the wrapper PID is EPERM (root process) and
# orphans pidstat, which keeps its since-unlinked output open and eats disk.
	$(Q)for pidfile in $(PIDS_DIR)/*.pid; do \
		if [ -f "$$pidfile" ]; then \
			pid=$$(cat "$$pidfile"); \
			sudo pkill -TERM -P $$pid $(ERR_REDIRECT) || true; \
			i=0; while sudo pgrep -P $$pid >/dev/null 2>&1 && [ $$i -lt 50 ]; do \
				sleep 0.2; i=$$((i+1)); \
			done; \
			sudo pkill -KILL -P $$pid $(ERR_REDIRECT) || true; \
			sudo kill $$pid $(ERR_REDIRECT) || true; \
		fi; \
	done
	$(Q)rm -rf "$(PIDS_DIR)"
	@echo "sysstat collection stopped"

.PHONY: csv-to-parquet
csv-to-parquet: ensure-results-exists
	$(Q)if [ -f "$(RESULTS_DIR)/sysstat/pidstat.out" ]; then \
		$(MAKE) parse; \
	fi

.PHONY: stop-collection
stop-collection: stop-profiling csv-to-parquet generate-stats

.PHONY: parse
parse: ensure-results-exists
	$(Q)python "./util/parse_output.py" "$(RESULTS_DIR)/sysstat" \
		$(ERR_REDIRECT) $(OUT_REDIRECT)
	$(Q)rm "$(RESULTS_DIR)/sysstat/pidstat.out"

.PHONY: generate-stats
generate-stats: ensure-results-exists
	$(Q)python "./util/generate_stats.py" \
		$(if $(COMM_FILTER),--process "$$(echo '$(COMM_FILTER)' | tr ',' ' ')") \
		$(if $(PID_FILTER),--pid "$$(echo '$(PID_FILTER)' | tr ',' ' ')") \
		$(if $(CONTAINER_FILTER),--container "$$(echo '$(CONTAINER_FILTER)' | tr ',' ' ')") \
		"$(RESULTS_DIR)" $(ERR_REDIRECT) $(OUT_REDIRECT)
	@echo "sysstat stats generated"

.PHONY: visualize
visualize: ensure-results-exists
	$(Q)python "./util/visualize.py" \
		$(if $(COMM_FILTER),--process "$$(echo '$(COMM_FILTER)' | tr ',' ' ')") \
		$(if $(PID_FILTER),--pid "$$(echo '$(PID_FILTER)' | tr ',' ' ')") \
		$(if $(CONTAINER_FILTER),--container "$$(echo '$(CONTAINER_FILTER)' | tr ',' ' ')") \
		"$(RESULTS_DIR)" $(ERR_REDIRECT) $(OUT_REDIRECT)
	$(Q)echo -e "sysstat visualization generated"
