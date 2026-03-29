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

.PHONY: start-collection
start-collection: ensure-results-exists ensure-sudo
	$(Q)echo -e "\nStarting sysstat collection.."

	$(Q)mkdir -p "$(PIDS_DIR)"

	$(Q)sudo $(PIDSTAT) -turd $(INTERVAL) \
		> "$(RESULTS_DIR)/sysstat/pidstat.out" \
		$(ERR_REDIRECT) & echo $$! > "$(PIDS_DIR)/pidstat.pid"

	$(Q)echo -e "sysstat collection is running!\n"

.PHONY: stop-profiling
stop-profiling:
	$(Q)for pidfile in $(PIDS_DIR)/*.pid; do \
		if [ -f "$$pidfile" ]; then \
			pid=$$(cat "$$pidfile"); \
			kill $$pid $(ERR_REDIRECT) || true; \
			i=0; while [ -d "/proc/$$pid" ] && [ $$i -lt 50 ]; do \
				sleep 0.2; i=$$((i+1)); \
			done; \
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
ifdef COMM_FILTER
	$(Q)python "./util/generate_stats.py" --process "$$(echo '$(COMM_FILTER)' | tr ',' ' ')" "$(RESULTS_DIR)" $(ERR_REDIRECT) $(OUT_REDIRECT)
else
	$(Q)python "./util/generate_stats.py" $(OPTIONS) "$(RESULTS_DIR)" $(ERR_REDIRECT) $(OUT_REDIRECT)
endif
	@echo "sysstat stats generated"

.PHONY: visualize
visualize: ensure-results-exists
ifdef COMM_FILTER
	$(Q)python "./util/visualize.py" --process "$$(echo '$(COMM_FILTER)' | tr ',' ' ')" "$(RESULTS_DIR)" $(ERR_REDIRECT) $(OUT_REDIRECT)
else
	$(Q)python "./util/visualize.py" "$(RESULTS_DIR)" $(ERR_REDIRECT) $(OUT_REDIRECT)
endif
	$(Q)echo -e "sysstat visualization generated"
