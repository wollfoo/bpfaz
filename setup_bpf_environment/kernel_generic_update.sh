#!/bin/bash
set -euo pipefail

# Yêu cầu root
[ "$(id -u)" -eq 0 ] || { echo "[ERROR] Phải chạy sudo/root."; exit 1; }

# Kiểm tra nếu hệ thống đã chạy kernel 6.8.0-60-generic thì thoát
if [ "$(uname -r)" = "6.8.0-60-generic" ]; then
  echo "[OK] Hệ thống đang chạy kernel 6.8.0-60-generic. Không cần thay đổi, thoát script." >&2
  exit 0
fi

echo "==> Cài/đảm bảo kernel generic HWE"
apt-get update -y
apt-get install -y --no-install-recommends \
  linux-image-generic-hwe-22.04 \
  linux-headers-generic-hwe-22.04 \
  linux-tools-generic-hwe-22.04 \
  linux-cloud-tools-generic-hwe-22.04

echo "==> Bật GRUB saved_entry"
sed -i 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT=saved/' /etc/default/grub
sed -i '/^GRUB_SAVEDEFAULT=/d' /etc/default/grub
echo 'GRUB_SAVEDEFAULT=true' >> /etc/default/grub

echo "==> Loại bỏ force-partuuid & override GRUB_DEFAULT"
rm -f /etc/default/grub.d/40-force-partuuid.cfg
sed -i 's/^GRUB_DEFAULT=.*/# &/' /etc/default/grub.d/*.cfg 2>/dev/null || true

# regenerate để bảo đảm menu đã có kernel generic
update-grub                                 # <── KHÔNG dùng -q

# xác định bản generic mới nhất
KVER_FULL=$(ls /boot/vmlinuz-*generic | sed 's|.*/vmlinuz-||' | sort -V | tail -1)
echo "   > Generic kernel: $KVER_FULL"

SUB=$(grep -m1 "^submenu 'Advanced options for Ubuntu'" /boot/grub/grub.cfg | cut -d"'" -f2)
MEN=$(grep -m1 "menuentry 'Ubuntu, with Linux ${KVER_FULL}'" /boot/grub/grub.cfg | cut -d"'" -f2 || true)
[ -n "$MEN" ] || { echo "[ERROR] Không tìm thấy menuentry."; exit 2; }

ENTRY="${SUB}>${MEN}"
grub-set-default "$ENTRY"
echo "   > GRUB entry: $ENTRY"

# đồng bộ grubenv nếu UEFI
if [ -d /sys/firmware/efi ]; then
  install -Dm644 /boot/grub/grubenv /boot/efi/EFI/ubuntu/grubenv
fi

echo "==> Khoá meta-package Azure"
apt-mark hold linux-azure linux-azure-6.8 >/dev/null 2>&1 || true

# hook xoá force-partuuid khi future upgrade
cat >/etc/apt/apt.conf.d/99-disable-force-partuuid <<'EOF'
DPkg::Post-Invoke {
  "if [ -f /etc/default/grub.d/40-force-partuuid.cfg ]; then rm -f /etc/default/grub.d/40-force-partuuid.cfg && update-grub; fi";
};
EOF

update-grub                                   # chạy lần cuối, không -q
echo "==> Rebooting vào kernel $KVER_FULL ..."
sleep 2
reboot
