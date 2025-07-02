# SPDX-License-Identifier: GPL-2.0
# Makefile cho net_cloak_bpf.c

TARGET = net_cloak
BPF_TARGET = ${TARGET:=_bpf}
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
KERN_RELEASE ?= $(shell uname -r)
KERN_HEADERS ?= /lib/modules/$(KERN_RELEASE)/build

# Compiler & Linker flags
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
CFLAGS ?= -g -O2 -Wall
BPF_CFLAGS ?= -g -O2 -Wall -target bpf -mcpu=v3 
DEBUG_CFLAGS ?= -g -O0 -Wall

# libbpf dependencies
LIBBPF_CFLAGS = -I/usr/include 
LIBBPF_LDFLAGS = -L/usr/lib -lbpf -lelf -lz

# Target architecture
ifeq ($(ARCH), x86)
  BPF_ARCH = x86
else ifeq ($(ARCH), arm64)
  BPF_ARCH = arm64
else 
  $(error Unsupported architecture $(ARCH))
endif

# Target directories
OUTDIR = ./output
OBJDIR = $(OUTDIR)/obj
INCLUDE_DIR = ./include
SRC_DIR = ./src

# Verify Kernel Headers
KERNEL_HAS_BTF := $(shell if [ -f $(KERN_HEADERS)/include/linux/btf.h ]; then echo 1; else echo 0; fi)

# Make directories
$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OUTDIR):
	mkdir -p $(OUTDIR)

# eBPF objects
$(OBJDIR)/$(BPF_TARGET).o: net_cloak_bpf.c | $(OBJDIR)
	$(CLANG) $(BPF_CFLAGS) -D__TARGET_ARCH_$(BPF_ARCH) -I$(INCLUDE_DIR) -I$(KERN_HEADERS)/arch/$(ARCH)/include \
		-I$(KERN_HEADERS)/arch/$(ARCH)/include/generated \
		-I$(KERN_HEADERS)/include \
		-I$(KERN_HEADERS)/arch/$(ARCH)/include/uapi \
		-I$(KERN_HEADERS)/arch/$(ARCH)/include/generated/uapi \
		-I$(KERN_HEADERS)/include/uapi \
		-I$(KERN_HEADERS)/include/generated/uapi \
		-c $< -o $@
	
# Generate BTF information if available
ifeq ($(KERNEL_HAS_BTF), 1)
$(OUTDIR)/$(BPF_TARGET).o: $(OBJDIR)/$(BPF_TARGET).o | $(OUTDIR)
	bpftool gen object $@ $<
else
$(OUTDIR)/$(BPF_TARGET).o: $(OBJDIR)/$(BPF_TARGET).o | $(OUTDIR)
	cp $< $@
endif

# Generate skeleton header file
$(OBJDIR)/$(BPF_TARGET).skel.h: $(OUTDIR)/$(BPF_TARGET).o | $(OBJDIR)
	bpftool gen skeleton $< > $@

# User-space loader program
$(OUTDIR)/attach_net_cloak: attach_net_cloak.c $(OBJDIR)/$(BPF_TARGET).skel.h $(OUTDIR)/$(BPF_TARGET).o | $(OUTDIR) 
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -I$(OBJDIR) $< -o $@ $(LIBBPF_CFLAGS) $(LIBBPF_LDFLAGS) 

# Command-line control utility
$(OUTDIR)/cloak_ctl: cloak_ctl.c | $(OUTDIR)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) $< -o $@ $(LIBBPF_CFLAGS) $(LIBBPF_LDFLAGS)

.PHONY: clean all build verify test install uninstall skeleton

all: build

build: $(OUTDIR)/$(BPF_TARGET).o $(OUTDIR)/attach_net_cloak $(OUTDIR)/cloak_ctl

skeleton: $(OBJDIR)/$(BPF_TARGET).skel.h
	@echo "Generated skeleton header: $<"

verify: $(OUTDIR)/$(BPF_TARGET).o
	bpftool prog load $< /sys/fs/bpf/$(TARGET) verbose

test: build
	./tests/run_tests.sh

clean:
	rm -rf $(OUTDIR)

install:
	install -m 0755 $(OUTDIR)/attach_net_cloak /usr/sbin/
	install -m 0755 $(OUTDIR)/cloak_ctl /usr/sbin/
	install -m 0644 $(OUTDIR)/$(BPF_TARGET).o /usr/lib/bpf/
	install -m 0644 ./netcloak.service /etc/systemd/system/
	@echo "Installation complete. Run 'systemctl enable --now netcloak' to start the service."

uninstall:
	rm -f /usr/sbin/attach_net_cloak
	rm -f /usr/sbin/cloak_ctl
	rm -f /usr/lib/bpf/$(BPF_TARGET).o
	systemctl disable --now netcloak || true
	rm -f /etc/systemd/system/netcloak.service 