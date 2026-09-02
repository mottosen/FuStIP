ifdef DEBUG
    Q =
    REDIRECT =
else
    Q = @
    REDIRECT = 1>/dev/null 2>&1
    MAKE_FLAGS += --no-print-directory
endif

# Correctness suite for the sysstat layer's cgroup v2 memory collection.
#
# The other suites compare against FIO's accounting. Memory has no such oracle,
# so each job here *constructs* its ground truth: workload.sh allocates exactly
# the requested anon/page-cache amounts and `docker run --memory` sets an
# exactly-known cap. check_test.py then asserts the collector saw them, plus the
# kernel identity memory.current ~= anon + file + kernel.
#
# The sysstat layer is mode-independent (always summary), so unlike the fio
# suites there is no MODE handling here.

MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SYSSTAT_DIR = ../../layers/sysstat

# Image for the workload container. alpine is ~8 MB and has every tool
# workload.sh needs (dd/head/tr/cat), so no image build is required.
TEST_IMAGE ?= alpine:latest

# The suite pins its own container name and uses it as the layer's container
# filter, the same way the fio suites force COMM_FILTER=fio regardless of what
# the caller passed.
MEM_CONTAINER = sysstat-memtest
# Host-process job (comm mode) — exercises the non-container resolution path.
# A copy of /bin/sh under this name runs workload.sh, because `comm` comes from
# the *executed binary*: running the script directly would exec /bin/sh via the
# shebang and report comm="sh", matching every other shell on the box. Keep the
# name under 15 characters — the kernel truncates comm to TASK_COMM_LEN-1.
COMM_LABEL = fustip-memtest
COMM_BIN = /tmp/$(COMM_LABEL)

DURATION ?= 20
STRESS_DURATION ?= 120

VAL_JOBS = val_page_cache val_anon val_capped val_comm
WORK_JOBS = work_mixed
STRESS_JOBS = stress_2m

.NOTPARALLEL:

.PHONY: ensure-sudo
ensure-sudo:
	$(Q)echo -e "\nEnsuring sudo is available.."
	$(Q)sudo -v
	$(Q)echo -e "Done!\n"

.PHONY: pull-image
pull-image:
	$(Q)docker image inspect $(TEST_IMAGE) >/dev/null 2>&1 || \
		docker pull $(TEST_IMAGE) $(REDIRECT)

.PHONY: clean-container
clean-container:
	$(Q)docker rm -f $(MEM_CONTAINER) $(REDIRECT) || true

# ── Aggregate targets ──

.PHONY: validate
validate: $(VAL_JOBS)

.PHONY: workload
workload: $(WORK_JOBS)

.PHONY: stress
stress: $(STRESS_JOBS)

.PHONY: all
all: validate workload stress

# ── Container job pattern ──
# $(1) job name, $(2) anon bytes, $(3) file bytes, $(4) docker --memory (empty
# for uncapped), $(5) extra check_test.py flags, $(6) duration, $(7) non-empty to
# start collection *before* the container.
#
# Ordering matters and differs by what the job asserts:
#
#   steady state ($(7) empty) — the container allocates and settles first, so the
#     window measures the held allocation rather than the ramp. Right for the
#     size assertions.
#   from the start ($(7) set) — collection begins first, so the allocation
#     happens inside the window. Required for the reclaim assertions: the
#     counters are cumulative and the checker takes a per-run delta, and under a
#     cap essentially all reclaim occurs while the workload is allocating. Settle
#     first and the window sees a quiet steady state with a delta of zero.
#     This also mirrors the cold startup profile, where profiling starts before
#     the containers come up.

define CONTAINER_JOB
.PHONY: $(1)
$(1): ensure-sudo pull-image
	$(Q)echo -e "\n============================================================"
	$(Q)echo -e "  Running: $(1)$(if $(PROFILER_CPUSET),  [collectors pinned to $(PROFILER_CPUSET)],  [collectors unpinned])"
	$(Q)echo -e "============================================================\n"
	$(Q)docker rm -f $(MEM_CONTAINER) $(REDIRECT) || true
	$(Q)rm -rf "$(RESULTS_DIR)/sysstat"
	$(Q)mkdir -p "$(RESULTS_DIR)/sysstat"
	$(if $(7),$(Q)$(MAKE) -C $(SYSSTAT_DIR) start-collection \
		CONTAINER_FILTER=$(MEM_CONTAINER) RESULTS_DIR=$(RESULTS_DIR) $(REDIRECT))
	$(Q)docker run -d --name $(MEM_CONTAINER) \
		$(if $(4),--memory=$(4)m) \
		-e ANON_BYTES=$(2) -e FILE_BYTES=$(3) -e DURATION=0 \
		-v "$(MAKEFILE_DIR)workload.sh:/workload.sh:ro" \
		$(TEST_IMAGE) sh /workload.sh $(REDIRECT)
	$(if $(7),,$(Q)sleep 8)
	$(if $(7),,$(Q)$(MAKE) -C $(SYSSTAT_DIR) start-collection \
		CONTAINER_FILTER=$(MEM_CONTAINER) RESULTS_DIR=$(RESULTS_DIR) $(REDIRECT))
	$(Q)sleep $(6)
	$(Q)$(MAKE) -C $(SYSSTAT_DIR) stop-profiling \
		CONTAINER_FILTER=$(MEM_CONTAINER) RESULTS_DIR=$(RESULTS_DIR) $(REDIRECT)
	$(Q)$(MAKE) -C $(SYSSTAT_DIR) csv-to-parquet \
		CONTAINER_FILTER=$(MEM_CONTAINER) RESULTS_DIR=$(RESULTS_DIR) $(REDIRECT)
	$(Q)$(MAKE) -C $(SYSSTAT_DIR) generate-stats \
		CONTAINER_FILTER=$(MEM_CONTAINER) RESULTS_DIR=$(RESULTS_DIR) $(REDIRECT)
	$(Q)docker rm -f $(MEM_CONTAINER) $(REDIRECT) || true
	$(Q)python $(MAKEFILE_DIR)check_test.py --job $(1) \
		--results-dir "$(RESULTS_DIR)" --label $(MEM_CONTAINER) \
		--duration $(6) $(5)
endef

# Page-cache dominant: 256 MB read into cache, no anonymous allocation. This is
# the regression test for the reason the collector exists — pidstat's rss_kb
# reports ~nothing here.
$(eval $(call CONTAINER_JOB,val_page_cache,0,268435456,,\
	--expect-file-mb 256 --expect-anon-mb 0,$(DURATION),))

# Anonymous dominant: the mirror image, so a collector that reported page cache
# as anon (or vice versa) fails one of the two.
$(eval $(call CONTAINER_JOB,val_anon,268435456,0,,\
	--expect-anon-mb 256 --expect-file-mb 0,$(DURATION),))

# Capped: 384 MB of demand against a 256 MB cap, so the kernel must reclaim.
# Asserts memory.max exactly and that the reclaim counters fired — the plumbing
# the memory-cap experiments depend on. Collects from the start (final arg): the
# reclaim happens while the workload allocates, and a per-run delta cannot see a
# burst that finished before the window opened. Sizes are not asserted here — the
# whole point is that the cap prevents the workload from holding what it asked for.
$(eval $(call CONTAINER_JOB,val_capped,134217728,268435456,256,\
	--expect-max-mb 256 --expect-reclaim,$(DURATION),collect-first))

# Mixed, uncapped: both components present and both known.
$(eval $(call CONTAINER_JOB,work_mixed,134217728,268435456,,\
	--expect-anon-mb 128 --expect-file-mb 256,$(DURATION),))

# Long run: catches sampling drift and cache staleness that a 20 s window hides.
$(eval $(call CONTAINER_JOB,stress_2m,134217728,268435456,,\
	--expect-anon-mb 128 --expect-file-mb 256,$(STRESS_DURATION),))

# ── Host-process job (comm mode, no container) ──
# Exercises the non-container resolution path: no container filter is passed, so
# the collector must find the process in /proc and resolve its host cgroup.
# Absolute sizes are not asserted — a host scope legitimately contains other
# processes — so this checks resolution, cadence and the kernel identity.

.PHONY: val_comm
val_comm: ensure-sudo
	$(Q)echo -e "\n============================================================"
	$(Q)echo -e "  Running: val_comm  [comm mode, no container]$(if $(PROFILER_CPUSET),  [collectors pinned to $(PROFILER_CPUSET)],  [collectors unpinned])"
	$(Q)echo -e "============================================================\n"
	$(Q)rm -rf "$(RESULTS_DIR)/sysstat"
	$(Q)mkdir -p "$(RESULTS_DIR)/sysstat"
	$(Q)cp /bin/sh $(COMM_BIN)
	$(Q)chmod +x $(COMM_BIN)
	$(Q)ANON_BYTES=134217728 FILE_BYTES=0 DURATION=$$(($(DURATION) + 15)) \
		$(COMM_BIN) $(MAKEFILE_DIR)workload.sh $(REDIRECT) & echo $$! > $(COMM_BIN).pid
	$(Q)sleep 5
	$(Q)$(MAKE) -C $(SYSSTAT_DIR) start-collection \
		COMM_FILTER=$(COMM_LABEL) RESULTS_DIR=$(RESULTS_DIR) $(REDIRECT)
	$(Q)sleep $(DURATION)
	$(Q)$(MAKE) -C $(SYSSTAT_DIR) stop-profiling \
		COMM_FILTER=$(COMM_LABEL) RESULTS_DIR=$(RESULTS_DIR) $(REDIRECT)
	$(Q)$(MAKE) -C $(SYSSTAT_DIR) csv-to-parquet \
		COMM_FILTER=$(COMM_LABEL) RESULTS_DIR=$(RESULTS_DIR) $(REDIRECT)
	$(Q)$(MAKE) -C $(SYSSTAT_DIR) generate-stats \
		COMM_FILTER=$(COMM_LABEL) RESULTS_DIR=$(RESULTS_DIR) $(REDIRECT)
	$(Q)kill $$(cat $(COMM_BIN).pid) 2>/dev/null || true
	$(Q)rm -f $(COMM_BIN) $(COMM_BIN).pid
	$(Q)python $(MAKEFILE_DIR)check_test.py --job val_comm \
		--results-dir "$(RESULTS_DIR)" --label $(COMM_LABEL) \
		--duration $(DURATION) --host-cgroup
