ifdef DEBUG
    Q =
else
    Q = @
    MAKEFLAGS += --no-print-directory
endif

MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Structural validation of an existing capture. Needs no root, no device and no
# workload — it only reads parquets — so it is the check to run against a tree
# produced elsewhere, or against one that migrate_event_schema.py has rewritten.
#
# RESULTS_DIR: one or more directories holding <layer>/detailed.parquet. A caller
# with its own tree layout expands the paths itself:
#   make -C tests/schema validate RESULTS_DIR="$(ls -d /path/*/results/search)"

.PHONY: validate
validate:
ifndef RESULTS_DIR
	$(error set RESULTS_DIR=<dir with nvme/block detailed.parquet> (several allowed))
endif
	$(Q)python3 "$(MAKEFILE_DIR)check_test.py" $(RESULTS_DIR)
