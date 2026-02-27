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

BPFTRACE := $(shell which bpftrace)
PIDS_DIR = /tmp/bpftrace_nvme-pids

INTERVAL ?= 1
MODE ?= summary

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

	$(Q)mkdir -p "$(RESULTS_DIR)/bpftrace"

	$(Q)echo -e "Results dir was found or created.\n"

.PHONY: start-collection
start-collection: ensure-results-exists ensure-sudo
	$(Q)echo -e "\nStarting bpftrace collection.."

	$(Q)mkdir -p "$(PIDS_DIR)"

	$(Q)sudo $(BPFTRACE) ./bt/$(MODE).bt "nvme0n1" \
		-o "$(RESULTS_DIR)/bpftrace/nvme-$(MODE).out" \
		$(ERR_REDIRECT) & echo $$! > "$(PIDS_DIR)/bpftrace-nvme-$(MODE).pid"

	$(Q)echo -e "bpftrace collection is running!\n"

.PHONY: stop-collection
stop-collection:
	$(Q)echo -e "\nStopping bpftrace collection.."

	$(Q)for pidfile in $(PIDS_DIR)/*.pid; do \
		if [ -f "$$pidfile" ]; then \
			kill $$(cat "$$pidfile") $(ERR_REDIRECT) || true; \
		fi; \
	done

	$(Q)rm -rf "$(PIDS_DIR)"

	$(Q)echo -e "Collection stopped!\n"
