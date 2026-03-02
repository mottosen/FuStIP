ifdef DEBUG
    Q =
    ERR_REDIRECT =
    MAKE_FLAGS =
else
    Q = @
    ERR_REDIRECT = 2>/dev/null
    MAKE_FLAGS = --no-print-directory
endif

MAKE := $(MAKE) $(MAKE_FLAGS)

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
	$(Q)echo -e "\nEnsuring results dir exists.."

	$(Q)if [ ! -d "$(RESULTS_DIR)" ]; then \
		echo "Results dir was not found: $(RESULTS_DIR)"; \
		exit 1; \
	fi

	$(Q)mkdir -p "$(RESULTS_DIR)/sysstat"

	$(Q)echo -e "Results dir was found or created.\n"

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
	$(Q)echo -e "\nStopping sysstat collection.."

	$(Q)for pidfile in $(PIDS_DIR)/*.pid; do \
		if [ -f "$$pidfile" ]; then \
			kill $$(cat "$$pidfile") $(ERR_REDIRECT) || true; \
		fi; \
	done

	$(Q)rm -rf "$(PIDS_DIR)"

	$(Q)echo -e "Collection stopped!\n"

	$(Q)sleep 2

	$(Q)$(MAKE) parse
	$(Q)$(MAKE) generate-stats

.PHONY: parse
parse: ensure-results-exists
	$(Q)echo -e "\nParsing sysstat output.."

	$(Q)python "./util/parse_output.py" "$(RESULTS_DIR)/sysstat" \
		$(ERR_REDIRECT) 1>&2

	$(Q)echo -e "Data parsed!\n"

	$(Q)rm "$(RESULTS_DIR)/sysstat/pidstat.out"

.PHONY: generate-stats
generate-stats: ensure-results-exists
	$(Q)echo -e "\nGenerating sysstat stats.."

	$(Q)python "./util/generate_stats.py" $(OPTIONS) "$(RESULTS_DIR)"

	$(Q)echo -e "Stats generated!\n"
