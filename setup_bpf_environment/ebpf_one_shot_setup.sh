#!/bin/bash
# ebpf_one_shot_setup.sh – One-shot bootstrap: nâng kernel Generic + cài môi trường eBPF
# Author: bpfaz team – 2025-07-04
# Usage: sudo ./ebpf_one_shot_setup.sh
#
# Nguyên lý:
# 1. Lần chạy đầu:
#    • Tạo systemd service (oneshot) để cài dev-env sau reboot.
#    • Gọi kernel_generic_update.sh (script này sẽ reboot).
# 2. Sau reboot, service tự chạy setup_dev_environment.sh → tạo marker DONE.
# 3. Những lần chạy sau, script thoát ngay (đã DONE).

set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MARKER_FILE="/var/run/ebpf_env_setup_done"
SERVICE_NAME="ebpf-postboot.service"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}"

# Nếu đã hoàn tất trước đó → thoát
if [[ -f "$MARKER_FILE" ]]; then
    echo "[INFO] eBPF dev environment đã được cài đặt trước đó – thoát."
    exit 0
fi

# ──────────────────────────────────────────────────────────────
# Tạo systemd service chạy sau reboot
# ──────────────────────────────────────────────────────────────

echo "[INFO] Đang tạo systemd service \"$SERVICE_NAME\" để cài dev-environment sau reboot..."

sudo tee "$SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=Post-boot eBPF dev-environment setup (bpfaz)
After=network-online.target
# Chỉ chạy nếu marker chưa tồn tại
ConditionPathExists=!$MARKER_FILE

[Service]
Type=oneshot
ExecStart=$BASE_DIR/setup_dev_environment.sh --verbose
ExecStartPost=/bin/touch $MARKER_FILE
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"

echo "[INFO] Đã enable service. Bắt đầu nâng cấp kernel Generic..."

# ──────────────────────────────────────────────────────────────
# Gọi script nâng cấp kernel (sẽ reboot khi hoàn tất)
# ──────────────────────────────────────────────────────────────

sudo bash "$BASE_DIR/kernel_generic_update.sh"

# Nếu vì lý do nào đó mà kernel script KHÔNG reboot,
# ta in nhắc nhở để user reboot thủ công.
echo "[WARN] kernel_generic_update.sh kết thúc mà không tự reboot."

# ──────────────────────────────────────────────────────────────
# Force reboot (fallback) – đảm bảo tự động khởi động lại
# ──────────────────────────────────────────────────────────────
echo "[INFO] Hệ thống sẽ tự reboot sau 1 giây ... (Ctrl+C để huỷ)"
sleep 1
reboot
