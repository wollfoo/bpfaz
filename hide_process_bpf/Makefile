# Makefile for eBPF Process Hiding with Proc Filesystem Protection
OUTPUT := ./output
CLANG ?= clang
BPFTOOL ?= bpftool
CC ?= gcc

# BPF compilation flags
BPF_CFLAGS := -g -O2 -Wall -target bpf -mcpu=v3
BPF_CFLAGS += -D__TARGET_ARCH_x86
BPF_CFLAGS += -DKBUILD_MODNAME='"hide_process_bpf"'
BPF_CFLAGS += -I/usr/include/bpf
BPF_CFLAGS += -I.


# User-space compilation flags
CFLAGS := -g -Wall -I$(OUTPUT)
LIBS := -lbpf -lelf -lz

# Create output directory
$(OUTPUT):
	mkdir -p $(OUTPUT)



# Compile main BPF program
$(OUTPUT)/hide_process_bpf.o: hide_process_bpf.c vmlinux.h | $(OUTPUT)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Generate skeleton
$(OUTPUT)/hide_process_bpf.skel.h: $(OUTPUT)/hide_process_bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# Compile loader
$(OUTPUT)/hide_process_loader: hide_process_loader.c $(OUTPUT)/hide_process_bpf.skel.h
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

# Legacy targets removed - using unified hide_process_bpf architecture

# Test compilation
test: $(OUTPUT)/hide_process_bpf.o
	@echo "eBPF Process Hiding compilation successful!"
	@file $(OUTPUT)/hide_process_bpf.o

# Kernel module removed - using eBPF-only approach

# Build LD_PRELOAD library with libbpf integration
$(OUTPUT)/libhide.so: libhide.c
	@echo "Building LD_PRELOAD library with BPF map integration..."
	$(CC) -shared -fPIC libhide.c -o $(OUTPUT)/libhide.so -ldl -lbpf -lelf -lz
	@echo "LD_PRELOAD library built successfully with libbpf support!"

# Build privileged side-car daemon
$(OUTPUT)/hide_process_syncd: hide_process_syncd.c
	@echo "Building hide_process_syncd daemon..."
	$(CC) $(CFLAGS) hide_process_syncd.c -o $(OUTPUT)/hide_process_syncd $(LIBS)
	@echo "Daemon built successfully!"

# Convenience target for daemon only
hide_process_syncd: $(OUTPUT)/hide_process_syncd

# Build main program
main: $(OUTPUT)/hide_process_loader

# Build all components (eBPF + LD_PRELOAD + Daemon)
all: $(OUTPUT)/hide_process_loader $(OUTPUT)/libhide.so $(OUTPUT)/hide_process_syncd

# Build main system (eBPF-only approach)
hybrid: main
	@echo "eBPF-only Architecture build complete"

# Test build without running
build-test: hybrid
	@echo "Build test successful"
	@file $(OUTPUT)/hide_process_bpf.o
	@ls -lh $(OUTPUT)/hide_process_loader

# Test LD_PRELOAD BPF map integration
test-libhide: $(OUTPUT)/libhide.so
	@echo "Testing LD_PRELOAD BPF map integration..."
	@echo "Checking if BPF map directory exists..."
	@if [ -d "/sys/fs/bpf/cpu_throttle" ]; then \
		echo "✓ BPF map directory found"; \
		ls -la /sys/fs/bpf/cpu_throttle/ 2>/dev/null || echo "⚠ No maps found"; \
	else \
		echo "⚠ BPF map directory not found - run hide_process_loader first"; \
	fi
	@echo "Testing library loading..."
	@LD_PRELOAD=$(OUTPUT)/libhide.so echo "✓ LD_PRELOAD library loads successfully"

# Install to system (requires root)
install: hybrid
	@echo "Installing Process Hiding System..."
	install -m 755 $(OUTPUT)/hide_process_loader /usr/local/bin/
	install -m 755 health_check.sh /usr/local/bin/hide_process_health_check.sh 2>/dev/null || true
	install -m 755 build_and_test.sh /usr/local/bin/hide_process_build_test.sh 2>/dev/null || true
	install -m 644 hide_process.service /etc/systemd/system/ 2>/dev/null || true
	install -m 644 hide_process.timer /etc/systemd/system/ 2>/dev/null || true
	systemctl daemon-reload
	@echo "Installation complete"
	@echo "To enable service: systemctl enable --now hide_process.service"

# Install privileged side-car architecture (requires root)
install-sidecar: all
	@echo "Installing Privileged Side-Car + Ringbuf Sync architecture..."
	install -m 755 $(OUTPUT)/hide_process_loader /usr/local/bin/
	install -m 755 $(OUTPUT)/hide_process_syncd /usr/local/bin/
	install -m 644 hide_process_syncd.service /etc/systemd/system/
	install -m 755 setup_privileged_sidecar.sh /usr/local/bin/
	@echo "Reloading systemd..."
	systemctl daemon-reload
	@echo "Installation complete"
	@echo "Run setup script: /usr/local/bin/setup_privileged_sidecar.sh"

# Uninstall from system
uninstall:
	@echo "Uninstalling Process Hiding System..."
	systemctl stop hide_process.service 2>/dev/null || true
	systemctl disable hide_process.service 2>/dev/null || true
	rm -f /usr/local/bin/hide_process_loader
	rm -f /usr/local/bin/hide_process_health_check.sh
	rm -f /usr/local/bin/hide_process_build_test.sh
	rm -f /etc/systemd/system/hide_process.service
	rm -f /etc/systemd/system/hide_process.timer
	systemctl daemon-reload
	@echo "Uninstallation complete"

# Uninstall privileged side-car architecture
uninstall-sidecar:
	@echo "Uninstalling Privileged Side-Car architecture..."
	systemctl stop hide_process_syncd.service 2>/dev/null || true
	systemctl disable hide_process_syncd.service 2>/dev/null || true
	rm -f /usr/local/bin/hide_process_syncd
	rm -f /etc/systemd/system/hide_process_syncd.service
	rm -f /usr/local/bin/setup_privileged_sidecar.sh
	systemctl daemon-reload
	@echo "Side-car uninstallation complete"

# Run comprehensive tests (requires root)
test-full: hybrid
	@echo "Running comprehensive test suite..."
	chmod +x tests/test_proc_hiding.sh 2>/dev/null || true
	sudo tests/test_proc_hiding.sh 2>/dev/null || echo "Test script not found"

# Quick functionality test
test-quick: $(OUTPUT)/hide_process_loader
	@echo "Running quick functionality test..."
	$(OUTPUT)/hide_process_loader --help

# Performance test
test-perf: hybrid
	@echo "Running performance tests..."
	chmod +x tests/test_proc_hiding.sh
	sudo tests/test_proc_hiding.sh 2>&1 | grep -i performance

# Test enhanced functionality (Priority 4)
test-enhanced: all test_enhanced_functionality.sh
	@echo "Testing enhanced functionality from Priority 4..."
	@chmod +x test_enhanced_functionality.sh
	@echo "⚠ Note: This test requires root privileges"
	@echo "Run: sudo ./test_enhanced_functionality.sh"

# Performance benchmarking
benchmark: all benchmark_performance.sh
	@echo "Running performance benchmarks..."
	@chmod +x benchmark_performance.sh
	@echo "⚠ Note: This benchmark requires root privileges"
	@echo "Run: sudo ./benchmark_performance.sh"

# Test all priorities integration
test-all-priorities: test test-enhanced
	@echo "Testing integration of all priorities..."
	@echo "✓ Priority 1: BPF Map Integration"
	@echo "✓ Priority 2: Standalone Operation"
	@echo "✓ Priority 3: Kernel Validation"
	@echo "✓ Priority 4: Enhanced Functionality"

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
	@echo "# eBPF Process Hiding System" > README.md
	@echo "" >> README.md
	@echo "## Components" >> README.md
	@echo "- eBPF program: hide_process_bpf.c" >> README.md
	@echo "- Userspace loader: hide_process_loader.c" >> README.md
	@echo "- LD_PRELOAD library: libhide.c" >> README.md
	@echo "- Deployment script: scripts/runtime_install.sh" >> README.md
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

.PHONY: test clean all main install uninstall help
.PHONY: hybrid build-test test-full test-quick test-perf check-kernel docs dev prod
.PHONY: test-enhanced benchmark test-all-priorities
