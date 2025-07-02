#!/bin/bash

# =====================================================
#  Performance Benchmark Script cho LSM Hide Optimization
#  So sánh hiệu suất trước và sau khi tối ưu hóa
# =====================================================

set -e

# Colors cho output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BENCHMARK_DURATION=60  # seconds
PROC_ACCESS_COUNT=10000
GETDENTS_COUNT=1000
STAT_COUNT=5000

echo -e "${BLUE}=== LSM Hide Performance Benchmark ===${NC}"
echo "Duration: ${BENCHMARK_DURATION}s per test"
echo "Proc access tests: ${PROC_ACCESS_COUNT}"
echo "Getdents tests: ${GETDENTS_COUNT}"
echo "Stat tests: ${STAT_COUNT}"
echo ""

# Function để measure syscall latency
measure_syscall_latency() {
    local syscall_type=$1
    local count=$2
    local output_file=$3
    
    echo -e "${YELLOW}Testing ${syscall_type} latency...${NC}"
    
    case $syscall_type in
        "openat")
            # Test openat syscall latency
            perf stat -e syscalls:sys_enter_openat,syscalls:sys_exit_openat \
                -o "$output_file" \
                bash -c "
                for i in \$(seq 1 $count); do
                    cat /proc/\$\$/status > /dev/null 2>&1 || true
                done
                " 2>&1
            ;;
        "getdents64")
            # Test getdents64 syscall latency
            perf stat -e syscalls:sys_enter_getdents64,syscalls:sys_exit_getdents64 \
                -o "$output_file" \
                bash -c "
                for i in \$(seq 1 $count); do
                    ls /proc > /dev/null 2>&1 || true
                done
                " 2>&1
            ;;
        "newfstatat")
            # Test stat syscall latency
            perf stat -e syscalls:sys_enter_newfstatat,syscalls:sys_exit_newfstatat \
                -o "$output_file" \
                bash -c "
                for i in \$(seq 1 $count); do
                    stat /proc/\$\$ > /dev/null 2>&1 || true
                done
                " 2>&1
            ;;
    esac
}

# Function để measure CPU usage
measure_cpu_usage() {
    local test_name=$1
    local duration=$2
    local output_file=$3
    
    echo -e "${YELLOW}Measuring CPU usage for ${test_name}...${NC}"
    
    # Start background process monitoring
    top -b -n1 | grep "lsm_hide" > "$output_file.cpu_before" 2>/dev/null || echo "0.0" > "$output_file.cpu_before"
    
    # Run test workload
    bash -c "
    for i in \$(seq 1 $((duration * 100))); do
        cat /proc/\$\$/status > /dev/null 2>&1 || true
        ls /proc > /dev/null 2>&1 || true
        stat /proc/\$\$ > /dev/null 2>&1 || true
        usleep 10000  # 10ms delay
    done
    " &
    
    local test_pid=$!
    sleep $duration
    kill $test_pid 2>/dev/null || true
    
    # Measure CPU after
    top -b -n1 | grep "lsm_hide" > "$output_file.cpu_after" 2>/dev/null || echo "0.0" > "$output_file.cpu_after"
}

# Function để measure memory usage
measure_memory_usage() {
    local output_file=$1
    
    echo -e "${YELLOW}Measuring memory usage...${NC}"
    
    # BPF memory usage
    bpftool map list | grep -E "(hidden_pid_map|events|proc_dir_filter)" > "$output_file.bpf_maps" 2>/dev/null || true
    
    # Process memory usage
    ps aux | grep lsm_hide | grep -v grep > "$output_file.process_mem" 2>/dev/null || echo "No lsm_hide process found" > "$output_file.process_mem"
    
    # Kernel memory từ /proc/meminfo
    grep -E "(MemTotal|MemFree|MemAvailable)" /proc/meminfo > "$output_file.kernel_mem"
}

# Function để run comprehensive benchmark
run_benchmark() {
    local test_name=$1
    local output_dir=$2
    
    echo -e "${GREEN}=== Running $test_name Benchmark ===${NC}"
    mkdir -p "$output_dir"
    
    # Syscall latency tests
    measure_syscall_latency "openat" $PROC_ACCESS_COUNT "$output_dir/openat_latency"
    measure_syscall_latency "getdents64" $GETDENTS_COUNT "$output_dir/getdents_latency"
    measure_syscall_latency "newfstatat" $STAT_COUNT "$output_dir/stat_latency"
    
    # CPU usage test
    measure_cpu_usage "$test_name" $BENCHMARK_DURATION "$output_dir/cpu_usage"
    
    # Memory usage test
    measure_memory_usage "$output_dir/memory_usage"
    
    # BPF program performance
    if command -v bpftool >/dev/null 2>&1; then
        echo -e "${YELLOW}Collecting BPF program statistics...${NC}"
        bpftool prog list | grep lsm_hide > "$output_dir/bpf_programs" 2>/dev/null || true
        bpftool map dump name hidden_pid_map > "$output_dir/hidden_pid_map_dump" 2>/dev/null || true
    fi
    
    echo -e "${GREEN}$test_name benchmark completed. Results in: $output_dir${NC}"
}

# Function để compare results
compare_results() {
    local before_dir=$1
    local after_dir=$2
    local comparison_file=$3
    
    echo -e "${BLUE}=== Performance Comparison ===${NC}"
    
    {
        echo "=== LSM Hide Performance Comparison ==="
        echo "Date: $(date)"
        echo ""
        
        echo "=== Syscall Latency Comparison ==="
        for syscall in openat getdents newfstatat; do
            echo "--- $syscall ---"
            if [[ -f "$before_dir/${syscall}_latency" && -f "$after_dir/${syscall}_latency" ]]; then
                echo "BEFORE:"
                grep -E "(task-clock|cycles|instructions)" "$before_dir/${syscall}_latency" 2>/dev/null || echo "No data"
                echo "AFTER:"
                grep -E "(task-clock|cycles|instructions)" "$after_dir/${syscall}_latency" 2>/dev/null || echo "No data"
            else
                echo "Missing data files"
            fi
            echo ""
        done
        
        echo "=== CPU Usage Comparison ==="
        echo "BEFORE:"
        cat "$before_dir/cpu_usage.cpu_before" 2>/dev/null || echo "No data"
        echo "AFTER:"
        cat "$after_dir/cpu_usage.cpu_after" 2>/dev/null || echo "No data"
        echo ""
        
        echo "=== Memory Usage Comparison ==="
        echo "BEFORE:"
        cat "$before_dir/memory_usage.process_mem" 2>/dev/null || echo "No data"
        echo "AFTER:"
        cat "$after_dir/memory_usage.process_mem" 2>/dev/null || echo "No data"
        echo ""
        
        echo "=== BPF Maps Comparison ==="
        echo "BEFORE:"
        cat "$before_dir/memory_usage.bpf_maps" 2>/dev/null || echo "No data"
        echo "AFTER:"
        cat "$after_dir/memory_usage.bpf_maps" 2>/dev/null || echo "No data"
        
    } > "$comparison_file"
    
    echo -e "${GREEN}Comparison results saved to: $comparison_file${NC}"
    cat "$comparison_file"
}

# Main execution
main() {
    local mode=${1:-"full"}
    local timestamp=$(date +%Y%m%d_%H%M%S)
    
    case $mode in
        "before")
            echo -e "${YELLOW}Running BEFORE optimization benchmark...${NC}"
            run_benchmark "BEFORE_OPTIMIZATION" "benchmark_results/before_$timestamp"
            ;;
        "after")
            echo -e "${YELLOW}Running AFTER optimization benchmark...${NC}"
            run_benchmark "AFTER_OPTIMIZATION" "benchmark_results/after_$timestamp"
            ;;
        "compare")
            local before_dir=${2:-"benchmark_results/before_latest"}
            local after_dir=${3:-"benchmark_results/after_latest"}
            compare_results "$before_dir" "$after_dir" "benchmark_results/comparison_$timestamp.txt"
            ;;
        "full")
            echo -e "${BLUE}Running full benchmark suite...${NC}"
            
            # Check if LSM Hide is running
            if ! pgrep lsm_hide_loader >/dev/null; then
                echo -e "${RED}Warning: lsm_hide_loader not running. Starting it...${NC}"
                sudo ./lsm_hide_loader &
                sleep 2
            fi
            
            # Run before benchmark (current implementation)
            run_benchmark "CURRENT_IMPLEMENTATION" "benchmark_results/current_$timestamp"
            
            echo -e "${YELLOW}Please apply optimizations and restart LSM Hide, then run:${NC}"
            echo -e "${YELLOW}$0 after${NC}"
            echo -e "${YELLOW}$0 compare benchmark_results/current_$timestamp benchmark_results/after_<timestamp>${NC}"
            ;;
        *)
            echo "Usage: $0 [before|after|compare|full]"
            echo "  before  - Run benchmark before optimization"
            echo "  after   - Run benchmark after optimization"
            echo "  compare - Compare before/after results"
            echo "  full    - Run complete benchmark suite"
            exit 1
            ;;
    esac
}

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    for cmd in perf bpftool top ps; do
        if ! command -v $cmd >/dev/null 2>&1; then
            missing_deps+=($cmd)
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo -e "${RED}Missing dependencies: ${missing_deps[*]}${NC}"
        echo "Install with: sudo apt-get install linux-tools-generic bpfcc-tools procps"
        exit 1
    fi
}

# Run dependency check
check_dependencies

# Execute main function
main "$@"
