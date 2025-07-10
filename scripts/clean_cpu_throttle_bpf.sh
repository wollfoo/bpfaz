#!/usr/bin/env bash
# clean_cpu_throttle_bpf.sh – Tiện ích dọn dẹp CPU Throttle eBPF
#
# Chức năng:
#   1. Dừng mọi tiến trình loader (attach_throttle)
#   2. Hủy liên kết & gỡ toàn bộ BPF prog có tên chứa "cpu_throttle_bpf"
#   3. Xóa thư mục maps ghim /sys/fs/bpf/cpu_throttle
#   4. In thông báo kết quả gọn gàng
#
# Sử dụng:
#   sudo ./clean_cpu_throttle_bpf.sh
#
set -euo pipefail

BPF_DIR="/sys/fs/bpf/cpu_throttle"
LOADER_PATTERN="attach_throttle"

info()  { echo -e "\e[32m[INFO]\e[0m $*"; }
warn()  { echo -e "\e[33m[WARN]\e[0m $*"; }
error() { echo -e "\e[31m[ERR ]\e[0m $*"; }

# Kiểm tra quyền root; nếu chưa phải root, tự gọi lại qua sudo
if [[ $EUID -ne 0 ]]; then
  echo -e "\e[33m[WARN]\e[0m Script không chạy với quyền root. Tự chuyển qua sudo..."
  exec sudo "$0" "$@"
fi

# 1. Dừng loader nếu còn
if pgrep -f "$LOADER_PATTERN" >/dev/null 2>&1; then
  info "Dừng tiến trình $LOADER_PATTERN..."
  pkill -f "$LOADER_PATTERN" || true
  sleep 1
else
  warn "Không tìm thấy tiến trình $LOADER_PATTERN đang chạy"
fi

# 2. Gỡ program cpu_throttle_bpf còn sót (nếu có)
if command -v bpftool >/dev/null; then
  mapfile -t IDS < <(bpftool prog list 2>/dev/null | grep cpu_throttle_bpf | awk '{print $1}' | tr -d ':')
  if [[ ${#IDS[@]} -gt 0 ]]; then
    for id in "${IDS[@]}"; do
      info "Gỡ prog ID=$id (cpu_throttle_bpf)"
      bpftool prog detach id "$id" 2>/dev/null || true
      bpftool prog delete id "$id" 2>/dev/null || true
    done
  else
    warn "Không có BPF prog cpu_throttle_bpf nào còn tồn tại"
  fi
else
  error "bpftool không có sẵn, bỏ qua bước gỡ prog"
fi

# 3. Xóa thư mục map ghim
if [[ -d "$BPF_DIR" ]]; then
  info "Xóa thư mục pin maps $BPF_DIR"
  rm -rf "$BPF_DIR"
else
  warn "Thư mục $BPF_DIR không tồn tại (đã được dọn trước đó)"
fi

info "Hoàn tất dọn dẹp cpu_throttle_bpf." 