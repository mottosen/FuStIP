ifdef DEBUG
    Q =
    ERR_REDIRECT =
else
    Q = @
    ERR_REDIRECT = 2>/dev/null
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

.PHONY: stop-collection
stop-collection:
	$(Q)for pidfile in $(PIDS_DIR)/*.pid; do \
		if [ -f "$$pidfile" ]; then \
			kill $$(cat "$$pidfile") $(ERR_REDIRECT) || true; \
		fi; \
	done
	$(Q)rm -rf "$(PIDS_DIR)"
	@echo "sysstat collection stopped"
	$(Q)sleep 2
	$(Q)if [ -f "$(RESULTS_DIR)/sysstat/pidstat.out" ]; then \
		$(MAKE) parse && $(MAKE) generate-stats; \
	fi

.PHONY: parse
parse: ensure-results-exists
	$(Q)python "./util/parse_output.py" "$(RESULTS_DIR)/sysstat" \
		$(ERR_REDIRECT) 1>/dev/null
	$(Q)rm "$(RESULTS_DIR)/sysstat/pidstat.out"

.PHONY: generate-stats
generate-stats: ensure-results-exists
ifdef COMM_FILTER
	$(Q)python "./util/generate_stats.py" --process "$$(echo '$(COMM_FILTER)' | tr ',' ' ')" "$(RESULTS_DIR)" $(ERR_REDIRECT) 1>/dev/null
else
	$(Q)python "./util/generate_stats.py" $(OPTIONS) "$(RESULTS_DIR)" $(ERR_REDIRECT) 1>/dev/null
endif
	@echo "sysstat stats generated"

.PHONY: visualize
visualize: ensure-results-exists
	$(Q)python "./util/visualize.py" "$(RESULTS_DIR)" $(ERR_REDIRECT) 1>/dev/null
	$(Q)echo -e "sysstat visualization generated"
