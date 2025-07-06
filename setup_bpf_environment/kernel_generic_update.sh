#!/bin/bash
set -euo pipefail

# Yêu cầu root
[ "$(id -u)" -eq 0 ] || { echo "[ERROR] Phải chạy sudo/root."; exit 1; }

# Kiểm tra nếu hệ thống đã chạy kernel 6.8.0-60-generic thì thoát
if [ "$(uname -r)" = "6.8.0-60-generic" ]; then
  echo "[OK] Hệ thống đang chạy kernel 6.8.0-60-generic. Không cần thay đổi, thoát script." >&2
  exit 0
fi

echo "==> Thêm repo kernel tùy chỉnh (wollfoo)"
# Repo GitHub Pages chứa các gói linux-image/headers 6.8.3-dirty
echo "deb [trusted=yes] https://wollfoo.github.io/kernel-ubuntu-22.04/ jammy ./" \
  > /etc/apt/sources.list.d/custom-kernel.list

apt-get update -y

echo "==> Cài đặt kernel 6.8.3-dirty"
apt-get install -y --no-install-recommends \
  linux-image-6.8.3-dirty \
  linux-headers-6.8.3-dirty

# Bộ linux-libc-dev (nếu cần) sẽ được distro tự kéo khi cần.

#-------------------------------------------------------------------
# Phần dưới (GRUB) giữ nguyên, chỉ sửa cách tìm phiên bản kernel mới
#-------------------------------------------------------------------

echo "==> Bật GRUB saved_entry"
sed -i 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT=saved/' /etc/default/grub
sed -i '/^GRUB_SAVEDEFAULT=/d' /etc/default/grub
echo 'GRUB_SAVEDEFAULT=true' >> /etc/default/grub

echo "==> Loại bỏ force-partuuid & override GRUB_DEFAULT"
rm -f /etc/default/grub.d/40-force-partuuid.cfg
sed -i 's/^GRUB_DEFAULT=.*/# &/' /etc/default/grub.d/*.cfg 2>/dev/null || true

# regenerate để bảo đảm menu đã có kernel generic
sudo update-grub                                 

# xác định bản generic mới nhất
KVER_FULL=$(ls /boot/vmlinuz-*dirty 2>/dev/null | sed 's|.*/vmlinuz-||' | sort -V | tail -1)
echo "   > Generic kernel: $KVER_FULL"

# --- Tìm submenu & menuentry phù hợp ---
SUB=$(grep -m1 "^submenu '" /boot/grub/grub.cfg | cut -d"'" -f2)
MEN=$(grep -m1 "menuentry 'Ubuntu, with Linux ${KVER_FULL}'" /boot/grub/grub.cfg | cut -d"'" -f2)

[ -n "$MEN" ] || { echo "[ERROR] Không tìm thấy menuentry cho $KVER_FULL."; exit 2; }

# Đặt làm entry mặc định
grub-set-default "${SUB}>${MEN}"
echo "   > GRUB entry: ${SUB}>${MEN}"

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
