# Makefile for eBPF LSM Hide with Proc Filesystem Protection
OUTPUT := ./output
CLANG ?= clang
BPFTOOL ?= bpftool
CC ?= gcc

# BPF compilation flags
BPF_CFLAGS := -g -O2 -Wall -target bpf -mcpu=v3
BPF_CFLAGS += -D__TARGET_ARCH_x86
BPF_CFLAGS += -DKBUILD_MODNAME='"lsm_hide_bpf"'
BPF_CFLAGS += -I/usr/include/bpf
BPF_CFLAGS += -I.

# User-space compilation flags
CFLAGS := -g -Wall -I$(OUTPUT)
LIBS := -lbpf -lelf -lz

# Create output directory
$(OUTPUT):
	mkdir -p $(OUTPUT)

# Compile main BPF program
$(OUTPUT)/lsm_hide_bpf.o: lsm_hide_bpf.c vmlinux.h | $(OUTPUT)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Generate skeleton
$(OUTPUT)/lsm_hide_bpf.skel.h: $(OUTPUT)/lsm_hide_bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# Compile loader
$(OUTPUT)/lsm_hide_loader: lsm_hide_loader.c $(OUTPUT)/lsm_hide_bpf.skel.h
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

# Legacy simple loader (for backward compatibility)
$(OUTPUT)/lsm_hide_simple.bpf.o: lsm_hide_simple.bpf.c vmlinux.h | $(OUTPUT)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(OUTPUT)/lsm_hide_simple.skel.h: $(OUTPUT)/lsm_hide_simple.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/simple_loader: simple_loader.c $(OUTPUT)/lsm_hide_simple.skel.h
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

# Test compilation
test: $(OUTPUT)/lsm_hide_bpf.o
	@echo "eBPF LSM Hide compilation successful!"
	@file $(OUTPUT)/lsm_hide_bpf.o

# Kernel module removed - using eBPF-only approach

# Build LD_PRELOAD library
$(OUTPUT)/libhide.so: libhide.c
	@echo "Building LD_PRELOAD library..."
	$(CC) -shared -fPIC -ldl libhide.c -o $(OUTPUT)/libhide.so
	@echo "LD_PRELOAD library built successfully!"

# Build main program
main: $(OUTPUT)/lsm_hide_loader

# Build all components (eBPF + LD_PRELOAD)
all: $(OUTPUT)/lsm_hide_loader $(OUTPUT)/libhide.so

# Build main system (eBPF-only approach)
hybrid: main
	@echo "eBPF-only Architecture build complete"

# Test build without running
build-test: hybrid
	@echo "Build test successful"
	@file $(OUTPUT)/lsm_hide_bpf.o
	@ls -lh $(OUTPUT)/loader_lsm_hide

# Install to system (requires root)
install: hybrid
	@echo "Installing LSM Hide Hybrid Architecture..."
	install -m 755 $(OUTPUT)/lsm_hide_loader /usr/local/bin/
	install -m 755 health_check.sh /usr/local/bin/lsm_hide_health_check.sh
	install -m 755 build_and_test.sh /usr/local/bin/lsm_hide_build_test.sh
	install -m 644 lsm_hide_health.service /etc/systemd/system/
	install -m 644 lsm_hide_health.timer /etc/systemd/system/
	systemctl daemon-reload
	@echo "Installation complete"
	@echo "To enable health monitoring: systemctl enable --now lsm_hide_health.timer"

# Uninstall from system
uninstall:
	@echo "Uninstalling LSM Hide..."
	systemctl stop lsm_hide_health.timer 2>/dev/null || true
	systemctl disable lsm_hide_health.timer 2>/dev/null || true
	rm -f /usr/local/bin/lsm_hide_loader
	rm -f /usr/local/bin/lsm_hide_health_check.sh
	rm -f /usr/local/bin/lsm_hide_build_test.sh
	rm -f /etc/systemd/system/lsm_hide_health.service
	rm -f /etc/systemd/system/lsm_hide_health.timer
	systemctl daemon-reload
	@echo "Uninstallation complete"

# Run comprehensive tests (requires root)
test-full: hybrid
	@echo "Running comprehensive test suite..."
	chmod +x tests/test_proc_hiding.sh
	sudo tests/test_proc_hiding.sh

# Quick functionality test
test-quick: $(OUTPUT)/lsm_hide_loader
	@echo "Running quick functionality test..."
	$(OUTPUT)/lsm_hide_loader --help

# Performance test
test-perf: hybrid
	@echo "Running performance tests..."
	chmod +x tests/test_proc_hiding.sh
	sudo tests/test_proc_hiding.sh 2>&1 | grep -i performance

# Check kernel compatibility
check-kernel:
	@echo "Checking kernel compatibility..."
	@echo "Current kernel: $$(uname -r)"
	@echo "Target kernel: 6.8.0-1026-azure"
	@if [ "$$(uname -r)" = "6.8.0-1026-azure" ]; then \
		echo "✓ Kernel version matches target"; \
	else \
		echo "⚠ Kernel version differs from target"; \
	fi

# Generate documentation
docs:
	@echo "Generating documentation..."
	@echo "# LSM Hide Hybrid Architecture" > README.md
	@echo "" >> README.md
	@echo "## Components" >> README.md
	@echo "- eBPF LSM program: lsm_hide_bpf.c" >> README.md
	@echo "- Userspace loader: loader_lsm_hide.c" >> README.md
	@echo "- Kernel module fallback: kernel_module/proc_hide_fallback.c" >> README.md
	@echo "- Health check system: health_check.sh" >> README.md
	@echo "" >> README.md
	@echo "## Build" >> README.md
	@echo "\`\`\`bash" >> README.md
	@echo "make hybrid" >> README.md
	@echo "\`\`\`" >> README.md
	@echo "" >> README.md
	@echo "## Install" >> README.md
	@echo "\`\`\`bash" >> README.md
	@echo "sudo make install" >> README.md
	@echo "\`\`\`" >> README.md
	@echo "Documentation generated: README.md"

# Clean everything
clean:
	rm -rf $(OUTPUT)
	rm -f README.md

# Development targets
dev: hybrid test-quick
	@echo "Development build complete"

# Production targets
prod: hybrid test-full install
	@echo "Production deployment complete"

.PHONY: test clean all main install uninstall
.PHONY: hybrid build-test test-full test-quick test-perf check-kernel docs dev prod
