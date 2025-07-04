# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
# Makefile tối ưu cho CPU Throttle với hỗ trợ đa kiến trúc và phụ thuộc tự động

# Biến môi trường
SHELL := /bin/bash
MAKEFLAGS += --no-print-directory

# Kiểm tra môi trường làm việc
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# Phát hiện kiến trúc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
VMLINUX_BTF_PATH ?= /sys/kernel/btf/vmlinux

# Phát hiện CPU vendor (Intel/AMD)
CPU_VENDOR := $(shell lscpu | grep "Vendor ID" | awk '{print $$3}' 2>/dev/null)

# Kiểm tra phiên bản kernel
KERNEL_VERSION := $(shell uname -r | cut -d'-' -f1)
KERNEL_MAJOR := $(shell echo $(KERNEL_VERSION) | cut -d'.' -f1)
KERNEL_MINOR := $(shell echo $(KERNEL_VERSION) | cut -d'.' -f2)

# Kiểm tra phiên bản clang
CLANG_VERSION := $(shell clang --version | grep -o "[0-9]\+\.[0-9]\+\.[0-9]\+" | head -1)
CLANG_MAJOR := $(shell echo $(CLANG_VERSION) | cut -d'.' -f1)
CLANG_MINOR := $(shell echo $(CLANG_VERSION) | cut -d'.' -f2)

# Đường dẫn tới bpftool
BPFTOOL := /usr/local/bin/bpftool

# Kiểm tra phụ thuộc
CHECK_DEPS := $(shell which $(BPFTOOL) > /dev/null && echo 1 || echo 0)
CHECK_LLVM := $(shell which llc > /dev/null && echo 1 || echo 0)
CHECK_CLANG := $(shell which clang > /dev/null && echo 1 || echo 0)

# Thiết lập đường dẫn tìm kiếm
INCLUDES = -I. -I$(shell pwd) -I/usr/include -I/usr/local/include

# Kiểm tra vmlinux.h
VMLINUX_H = $(wildcard ./vmlinux.h)
ifeq ($(VMLINUX_H),)
  $(info [WARN] vmlinux.h không tìm thấy. Sẽ tự động tạo...)
endif

# Kiểm tra BTF khả dụng
HAS_BTF := $(shell if [ -f $(VMLINUX_BTF_PATH) ]; then echo 1; else echo 0; fi)

# Cài đặt RDT
HAS_RDT := 0
RDT_FLAGS :=
RDT_LIBS :=

ifeq ($(CPU_VENDOR),GenuineIntel)
  ifneq ($(wildcard /usr/include/pqos.h),)
    HAS_RDT := 1
    RDT_FLAGS += -DHAS_RDT
    RDT_LIBS += -lpqos
    $(info [INFO] Phát hiện hỗ trợ Intel RDT)
  else
    $(info [INFO] Intel CPU phát hiện, nhưng thư viện RDT (pqos.h) không tìm thấy. Xem xét cài đặt intel-cmt-cat.)
  endif
endif

# Cài đặt thư viện MSR
HAS_MSR := $(shell if [ -e /dev/cpu/0/msr ]; then echo 1; else echo 0; fi)
ifeq ($(HAS_MSR),1)
  $(info [INFO] MSR access khả dụng)
else
  $(info [WARN] MSR access không khả dụng. Một số tính năng có thể bị giới hạn.)
endif

# Thiết lập LLVM và clang
LLC ?= llc
CLANG ?= clang
CC ?= gcc
OPT ?= opt

# Cài đặt thông số BTF
ifneq ($(and $(shell test $(KERNEL_MAJOR) -ge 5 && echo 1),$(shell test $(KERNEL_MINOR) -ge 8 && echo 1)),)
  BTF_PARAMS := --btf
else
  BTF_PARAMS :=
  $(info [WARN] Kernel < 5.8, BTF không được hỗ trợ)
endif

# Thiết lập libbpf
LIBBPF_SRC = $(abspath ./libbpf/src)
LIBBPF_OBJ = $(abspath ./build/libbpf.a)

# Cài đặt seccomp (nếu có)
HAS_SECCOMP := $(shell if [ -f /usr/include/seccomp.h ]; then echo 1; else echo 0; fi)
ifeq ($(HAS_SECCOMP),1)
  SECCOMP_FLAGS := -DLIBSECCOMP_AVAILABLE
  SECCOMP_LIBS := -lseccomp
  $(info [INFO] Seccomp filtering được hỗ trợ)
else
  SECCOMP_FLAGS :=
  SECCOMP_LIBS :=
endif

# Các thư mục output
BUILD_DIR = ./build
OBJ_DIR = ./obj
CACHE_DIR = ./btf_cache
TEST_DIR = ./tests

# Tùy chọn cho clang
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 | sed -n '/<...> search starts here:/,/End of search list./p' | sed -e '1d' -e '$d')
COMMON_FLAGS := -g -O2 -Wall -Wextra

# Cài đặt tùy chọn biên dịch tùy chỉnh
ifeq ($(ARCH),arm64)
  COMMON_FLAGS += -D__aarch64__
  $(info [INFO] Biên dịch cho kiến trúc ARM64)
else ifeq ($(ARCH),x86)
  COMMON_FLAGS += -D__x86_64__
  $(info [INFO] Biên dịch cho kiến trúc x86_64)
endif

# Tùy chọn cho BPF
BPF_CFLAGS = -g -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(RDT_FLAGS) $(SECCOMP_FLAGS)

ifeq ($(HAS_BTF), 1)
    BPF_CFLAGS += -DHAS_BTF
endif

# Khởi tạo biến environments
DEBUG ?= 0
STATIC ?= 0
THREADS ?= $(shell nproc 2>/dev/null || echo 1)
WITH_RDT ?= $(HAS_RDT)
WITH_SECCOMP ?= $(HAS_SECCOMP)

ifeq ($(DEBUG),1)
    COMMON_FLAGS += -DDEBUG -g3
    BPF_CFLAGS += -DDEBUG
endif

ifeq ($(STATIC),1)
    LDFLAGS += -static
endif

# Thêm tùy chọn libbpf
CFLAGS += $(COMMON_FLAGS)
BPF_CFLAGS += $(COMMON_FLAGS)
BPF_CFLAGS += -target bpf -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign -D__linux__ -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end -Wno-address-of-packed-member -Wno-tautological-compare -Wno-unknown-warning-option -fno-asynchronous-unwind-tables -Wunused

# Các tệp nguồn chính
BPF_SRCS = cpu_throttle_bpf.c
APP_SRCS = attach_throttle.c
CTL_SRCS = throttle_ctl.c
HELPER_SRCS =

# Các tệp kiểm thử mới
TEST_CPU_THROTTLE = cpu_throttle_bpf/tests/test_cpu_throttle.c
TEST_CLOAKING = cpu_throttle_bpf/tests/test_cloaking.c
TEST_SRCS = $(TEST_CPU_THROTTLE) $(TEST_CLOAKING)

# Mục tiêu đầu ra
APP_TARGET = $(OBJ_DIR)/attach_throttle
CTL_TARGET = $(OBJ_DIR)/throttle_ctl
BPF_TARGET = $(OBJ_DIR)/cpu_throttle_bpf.bpf.o
SKEL_TARGET = $(OBJ_DIR)/cpu_throttle_bpf.skel.h

# Mục tiêu kiểm thử
TEST_CPU_THROTTLE_TARGET = tests/test_cpu_throttle
TEST_CLOAKING_TARGET = tests/test_cloaking
TEST_TARGETS = $(TEST_CPU_THROTTLE_TARGET) $(TEST_CLOAKING_TARGET)

# Các thư viện liên kết
LIBS = -lelf -lz -lbpf -lpthread -lm $(RDT_LIBS) $(SECCOMP_LIBS)

# Mục tiêu chính
.PHONY: all
all: app

# Kiểm tra các phụ thuộc
.PHONY: check-deps
check-deps:
	@if [ $(CHECK_DEPS) -eq 0 ]; then echo "ERROR: $(BPFTOOL) không tìm thấy"; exit 1; fi
	@if [ $(CHECK_LLVM) -eq 0 ]; then echo "ERROR: llc không tìm thấy"; exit 1; fi
	@if [ $(CHECK_CLANG) -eq 0 ]; then echo "ERROR: clang không tìm thấy"; exit 1; fi
	@if [ $(CLANG_MAJOR) -lt 10 ]; then echo "WARN: clang $(CLANG_VERSION) có thể quá cũ. Khuyến nghị >= 10.0.0"; fi
	@echo "Kiểm tra phụ thuộc hoàn tất."

# Chuẩn bị thư mục làm việc
.PHONY: prepare
prepare:
	@mkdir -p $(OBJ_DIR) $(BUILD_DIR) $(CACHE_DIR) $(TEST_DIR)

# Tạo vmlinux.h nếu chưa có
.PHONY: vmlinux
vmlinux: prepare
	@if [ ! -f ./vmlinux.h ]; then \
		echo "Đang tạo vmlinux.h từ hệ thống"; \
		if [ -f $(VMLINUX_BTF_PATH) ]; then \
			$(BPFTOOL) btf dump file $(VMLINUX_BTF_PATH) format c > ./vmlinux.h; \
		else \
			echo "BTF không có sẵn, thử tạo vmlinux.h từ headers"; \
			./gen_vmlinux_h.sh > ./vmlinux.h || \
			(echo "Tạo vmlinux.h thất bại. Vui lòng cài đặt $(BPFTOOL) hoặc kheaders module"; \
			exit 1); \
		fi; \
	fi

# Tối ưu vmlinux.h
.PHONY: vmlinux_slim
vmlinux_slim: vmlinux
	@echo "Tối ưu vmlinux.h"
	@grep -v "__attribute__((preserve_access_index))" ./vmlinux.h > ./vmlinux_slim.h
	@mv ./vmlinux_slim.h ./vmlinux.h

# Kiểm tra bpftool có sẵn không
.PHONY: check-tools
check-tools: 
	@echo "Sử dụng bpftool từ /usr/local/bin"
	@which $(BPFTOOL) > /dev/null || (echo "ERROR: $(BPFTOOL) không được tìm thấy trong PATH"; exit 1)
	@$(BPFTOOL) --version

# Tạo BPF object và skeleton
$(OBJ_DIR)/%.bpf.o: %.bpf.c vmlinux check-tools
	@mkdir -p $(dir $@)
	@echo "Biên dịch $<"
	@$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "Tạo BTF debug info cho $@"
	@if [ -d "/sys/kernel/btf" ]; then \
		mkdir -p $(CACHE_DIR); \
		CACHE_FILE=$(CACHE_DIR)/$(shell echo $< | md5sum | cut -d ' ' -f1).btf; \
		if [ -f $$CACHE_FILE ]; then \
			echo "Sử dụng BTF cache cho $<"; \
			cp $$CACHE_FILE $(OBJ_DIR)/$*.bpf.btf; \
		else \
			echo "Tạo BTF info mới cho $<"; \
			$(BPFTOOL) gen skeleton $@ > $(@:.o=.skel.h); \
		fi; \
	else \
		echo "BTF không khả dụng trên hệ thống này"; \
		$(BPFTOOL) gen skeleton $@ > $(@:.o=.skel.h); \
	fi

.PHONY: skeleton
skeleton: $(BPF_TARGET)
	@echo "Tạo skeleton header từ $<"
	@$(BPFTOOL) gen skeleton $< > $(SKEL_TARGET)
	@cp $(SKEL_TARGET) ./cpu_throttle_bpf.skel.h

# Thu thập thông tin phiên bản
.PHONY: version
version:
	@mkdir -p $(BUILD_DIR)
	@echo -n "#define BUILD_VERSION \"" > $(BUILD_DIR)/version.h
	@git describe --tags --always 2>/dev/null || echo "unknown" | tr -d '\n' >> $(BUILD_DIR)/version.h
	@echo "\"" >> $(BUILD_DIR)/version.h
	@echo -n "#define BUILD_DATE \"" >> $(BUILD_DIR)/version.h
	@date +"%Y-%m-%d %H:%M:%S" | tr -d '\n' >> $(BUILD_DIR)/version.h
	@echo "\"" >> $(BUILD_DIR)/version.h
	@echo -n "#define BUILD_ARCH \"" >> $(BUILD_DIR)/version.h
	@echo -n "$(ARCH)" >> $(BUILD_DIR)/version.h
	@echo "\"" >> $(BUILD_DIR)/version.h

# Biên dịch chương trình user-space
.PHONY: app
app: $(BPF_TARGET) skeleton version
	@echo "Biên dịch chương trình attach_throttle_v2"
	@$(CC) $(CFLAGS) $(INCLUDES) $(APP_SRCS) $(LDFLAGS) $(LIBS) -o $(APP_TARGET)
	@echo "Biên dịch hoàn tất: $(APP_TARGET)"

# Biên dịch throttle_ctl
.PHONY: ctl
ctl: $(BPF_TARGET) skeleton version
	@echo "Biên dịch chương trình throttle_ctl"
	@$(CC) $(CFLAGS) $(INCLUDES) $(CTL_SRCS) $(LDFLAGS) $(LIBS) -o $(CTL_TARGET)
	@echo "Biên dịch hoàn tất: $(CTL_TARGET)"

# Kiểm tra mã nguồn
.PHONY: check
check: $(BPF_TARGET)
	@echo "Kiểm tra mã nguồn BPF"
	@$(BPFTOOL) prog dump xlated file $(BPF_TARGET) 2>&1 | grep "invalid\|error" && echo "Có lỗi trong mã BPF" || echo "Mã BPF hợp lệ"

# Tạo tài liệu API
.PHONY: docs
docs:
	@echo "# CPU Throttle API Documentation" > api_documentation.md
	@echo "" >> api_documentation.md
	@echo "## Core APIs" >> api_documentation.md
	@echo "..." >> api_documentation.md
	@echo "Tạo tài liệu API hoàn tất."

# Vệ sinh
.PHONY: clean
clean:
	@rm -rf $(OBJ_DIR)/* $(BUILD_DIR)/*
	@echo "Đã dọn dẹp các tệp build"

.PHONY: cleanall
cleanall: clean
	@rm -rf $(OBJ_DIR) $(BUILD_DIR) $(CACHE_DIR) $(TEST_TARGETS)
	@echo "Đã dọn dẹp tất cả"

# Cài đặt vào thư mục system
.PHONY: install
install: app ctl
	@echo "Cài đặt vào /usr/local/bin"
	@mkdir -p /usr/local/bin
	@cp $(APP_TARGET) /usr/local/bin/
	@cp $(CTL_TARGET) /usr/local/bin/
	@chmod 755 /usr/local/bin/$(notdir $(APP_TARGET))
	@chmod 755 /usr/local/bin/$(notdir $(CTL_TARGET))
	@echo "Cài đặt hoàn tất"

# Test thử chương trình
.PHONY: test
test: app
	@echo "Chạy thử nghiệm: cần root để tải eBPF"
	@if [ $$(id -u) -eq 0 ]; then \
		./$(APP_TARGET) -v; \
	else \
		echo "Cần quyền root để chạy test!"; \
		sudo ./$(APP_TARGET) -v || true; \
	fi

# Show thông tin biên dịch
.PHONY: info
info:
	@echo "Thông tin biên dịch:"
	@echo "  Kiến trúc: $(ARCH)"
	@echo "  Kernel: $(KERNEL_VERSION) ($(KERNEL_MAJOR).$(KERNEL_MINOR))"
	@echo "  Clang: $(CLANG_VERSION)"
	@echo "  BTF: $(HAS_BTF)"
	@echo "  RDT: $(HAS_RDT)"
	@echo "  MSR: $(HAS_MSR)"
	@echo "  Seccomp: $(HAS_SECCOMP)"