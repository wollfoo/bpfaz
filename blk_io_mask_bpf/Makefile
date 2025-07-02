# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
# Makefile cho blk_io_mask_bpf module

SHELL := /bin/bash
OBJ_DIR := obj
OUT_DIR := output
BPF_OBJ := $(OBJ_DIR)/blk_io_mask_bpf.o
SKEL_HDR := $(OBJ_DIR)/blk_io_mask_bpf.skel.h
APP_OBJ := $(OBJ_DIR)/attach_blk_io_mask
CTL_OBJ := $(OBJ_DIR)/blk_mask_ctl
ADAPTIVE_OBJ := $(OBJ_DIR)/adaptive_masking.o
PROM_OBJ := $(OBJ_DIR)/prometheus_exporter

BPF_SRC := blk_io_mask_bpf.c
APP_SRC := attach_blk_io_mask.c
CTL_SRC := blk_mask_ctl.c
ADAPTIVE_SRC := adaptive_masking.c
PROM_SRC := prometheus_exporter.c

CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool
CC ?= gcc

# Cờ biên dịch cải tiến
KERNEL_VERSION := $(shell uname -r | cut -d'.' -f1,2)
COMMON_FLAGS := -O2 -g -Wall -Wextra -Werror -fstack-protector-strong
SECURITY_FLAGS := -D_FORTIFY_SOURCE=2 -fPIE -fstack-clash-protection -fcf-protection=full
FORMAT_FLAGS := -Wformat -Wformat-security -Wformat-overflow=2 -Wunused -Wconversion
HARDENING_FLAGS := -fno-common -ftrivial-auto-var-init=zero -fzero-call-used-regs=used-gpr

# Cờ biên dịch cho mã userspace
CFLAGS := $(COMMON_FLAGS) $(SECURITY_FLAGS) $(FORMAT_FLAGS) $(HARDENING_FLAGS)

# Tối ưu cờ biên dịch cho BPF dựa trên phiên bản kernel
BPF_BASIC_FLAGS := -target bpf -D__TARGET_ARCH_x86
ifeq ($(shell echo "$(KERNEL_VERSION) >= 5.10" | bc), 1)
    BPF_VER_FLAGS := -D__BPF_TRACING__
    BPF_OPT_FLAGS := -O2 -g
else
    BPF_VER_FLAGS := -DCOMPAT_NEED_CORE_READ
    BPF_OPT_FLAGS := -O2 -g
endif

# BTF flags for Kernel 5.4+
ifeq ($(shell echo "$(KERNEL_VERSION) >= 5.4" | bc), 1)
    BTF_FLAGS := -Xclang -target-feature -Xclang +btf
    $(info [INFO] Enabling BTF features for kernel $(KERNEL_VERSION))
else
    BTF_FLAGS :=
    $(info [WARN] BTF features not enabled for kernel $(KERNEL_VERSION))
endif

BPF_CFLAGS := $(BPF_OPT_FLAGS) $(BPF_BASIC_FLAGS) $(BPF_VER_FLAGS) $(BTF_FLAGS) -Wall -Werror

# Link libraries
LIBS := -lelf -lz -lbpf -lpthread -lm -ldl
SECCOMP_LIBS := -lseccomp
CRYPTO_LIBS := -lcrypto -lssl

# Detect vmlinux.h
VMLINUX_H := vmlinux.h
ifneq ($(wildcard $(VMLINUX_H)),)
  $(info [INFO] Sử dụng vmlinux.h hiện có)
else
  $(info [INFO] Tải vmlinux.h bằng bpftool btf dump)
  $(shell $(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h)
endif

all: dirs $(APP_OBJ) $(CTL_OBJ) $(PROM_OBJ)

.PHONY: dirs
dirs:
	@mkdir -p $(OBJ_DIR) $(OUT_DIR)

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX_H)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(BPFTOOL) gen skeleton $@ > $(SKEL_HDR)

$(ADAPTIVE_OBJ): $(ADAPTIVE_SRC)
	$(CC) $(CFLAGS) -I. -I$(OBJ_DIR) -c $< -o $@

$(APP_OBJ): $(APP_SRC) $(BPF_OBJ)
	$(CC) $(CFLAGS) -I. -I$(OBJ_DIR) $< -o $@ $(LIBS) $(SECCOMP_LIBS) -fPIE -pie

$(CTL_OBJ): $(CTL_SRC) $(SKEL_HDR) $(ADAPTIVE_OBJ)
	$(CC) $(CFLAGS) -I. -I$(OBJ_DIR) $< $(ADAPTIVE_OBJ) -o $@ $(LIBS) -fPIE -pie

$(PROM_OBJ): $(PROM_SRC) $(SKEL_HDR)
	$(CC) $(CFLAGS) -I. -I$(OBJ_DIR) $< -o $@ $(LIBS) $(CRYPTO_LIBS) -fPIE -pie
	@cp $(APP_OBJ) $(CTL_OBJ) $(PROM_OBJ) $(OUT_DIR)/

install: all
	@sudo install -m 0755 $(OUT_DIR)/attach_blk_io_mask /usr/local/sbin/
	@sudo install -m 0755 $(OUT_DIR)/blk_mask_ctl /usr/local/sbin/
	@sudo install -m 0755 $(OUT_DIR)/prometheus_exporter /usr/local/sbin/
	@sudo install -m 0644 blk_mask.service /etc/systemd/system/
	@echo "Installed. Use 'sudo systemctl daemon-reload' to reload systemd."
	@if ! getent group blkio >/dev/null; then \
		sudo groupadd blkio; \
		echo "Created blkio group"; \
	fi

clean:
	rm -rf $(OBJ_DIR) $(OUT_DIR)

.PHONY: clean install 