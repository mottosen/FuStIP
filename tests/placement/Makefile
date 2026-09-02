ifdef DEBUG
    Q =
else
    Q = @
    MAKEFLAGS += --no-print-directory
endif

# Collector-placement suite (PROFILER_CPUSET).
#
# Unlike the fio suites this one needs no root, no device and no workload: what
# PROFILER_CPUSET changes is the command line each layer launches, which `make -n`
# settles without running anything. That is deliberate — it makes the suite cheap
# enough to run on every change rather than only when someone has a spare NVMe.
#
# It is also the only suite that can run in CI or on a laptop, so it is the one
# that guards backwards compatibility: with PROFILER_CPUSET unset, every layer must
# emit exactly the command it emitted before the option existed.

MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

.PHONY: all validate help

all: validate

help:
	@echo "Collector-placement suite (PROFILER_CPUSET)"
	@echo ""
	@echo "  make validate   - assert the placement contract (no root, no device, ~1s)"
	@echo ""
	@echo "Checks: every launch site is unpinned by default; setting PROFILER_CPUSET"
	@echo "prefixes taskset and changes nothing else; an impossible cpuset is refused"
	@echo "at parse time; an empty one means unpinned rather than invalid."

validate:
	$(Q)python3 "$(MAKEFILE_DIR)check_test.py"
