ifdef DEBUG
    Q =
else
    Q = @
endif

CLANG := $(shell which clang)
BPFTOOL ?= bpftool
CC ?= cc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
INCLUDE_DIR = ../../../util/bpf/include

.PHONY: all clean

all: standalone

# ── vmlinux.h generation ──

$(INCLUDE_DIR)/vmlinux.h:
	$(Q)mkdir -p $(INCLUDE_DIR)
	$(Q)echo "Generating vmlinux.h..."
	$(Q)$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# ── Standalone (BPF + userspace loader) ──

c/standalone.bpf.o: c/standalone.bpf.c ../bpf/bpf_core.h $(INCLUDE_DIR)/vmlinux.h
	$(Q)echo "  CLANG   $@"
	$(Q)NIX_HARDENING_ENABLE="" $(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I$(INCLUDE_DIR) -I.. \
		-c $< -o $@

c/standalone.skel.h: c/standalone.bpf.o
	$(Q)echo "  SKEL    $@"
	$(Q)$(BPFTOOL) gen skeleton $< > $@

standalone: c/loader.c c/standalone.skel.h
	$(Q)echo "  CC      c/standalone"
	$(Q)$(CC) -g -O2 -Wall -Ic/ -o c/standalone $< -lbpf -lelf -lz

# ── IG gadget build ──

IG ?= $(ROOT_DIR)/subs/inspektor-gadget/ig
IG_TAG ?= fustip-nvme:latest

.PHONY: ig-build
ig-build:
	$(Q)echo "  IG-BUILD $(IG_TAG)"
	$(Q)sudo $(IG) image build -f ig-build.yaml -t $(IG_TAG) .

# ── Clean ──

clean:
	$(Q)rm -f c/*.bpf.o c/*.skel.h c/standalone
