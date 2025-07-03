#!/bin/bash
# =====================================================
#  Setup script for Privileged Side-Car + Ringbuf Sync
#  Configures permissions and systemd service
# =====================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="hide_process_syncd"
DAEMON_PATH="/usr/local/bin/${SERVICE_NAME}"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
SOCKET_DIR="/run/hide_process"
GROUP_NAME="bpfusers"

echo "Setting up Privileged Side-Car + Ringbuf Sync architecture..."

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Create bpfusers group if it doesn't exist
if ! getent group "$GROUP_NAME" > /dev/null 2>&1; then
    echo "Creating group: $GROUP_NAME"
    groupadd "$GROUP_NAME"
else
    echo "Group $GROUP_NAME already exists"
fi

# Build the daemon
echo "Building hide_process_syncd daemon..."
cd "$SCRIPT_DIR"
if ! make hide_process_syncd; then
    echo "Failed to build daemon"
    exit 1
fi

# Install daemon binary
echo "Installing daemon to $DAEMON_PATH"
cp "${SCRIPT_DIR}/output/hide_process_syncd" "$DAEMON_PATH"
chmod 755 "$DAEMON_PATH"
chown root:root "$DAEMON_PATH"

# Install systemd service
echo "Installing systemd service..."
cp "${SCRIPT_DIR}/${SERVICE_NAME}.service" "$SERVICE_PATH"
chmod 644 "$SERVICE_PATH"
chown root:root "$SERVICE_PATH"

# Create socket directory
echo "Creating socket directory: $SOCKET_DIR"
mkdir -p "$SOCKET_DIR"
chown root:"$GROUP_NAME" "$SOCKET_DIR"
chmod 750 "$SOCKET_DIR"

# Reload systemd and enable service
echo "Configuring systemd service..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

# Check if BPF maps exist
BPF_MAP_DIR="/sys/fs/bpf/cpu_throttle"
if [[ ! -d "$BPF_MAP_DIR" ]]; then
    echo "Warning: BPF maps directory not found: $BPF_MAP_DIR"
    echo "Please load the BPF program first using hide_process_loader"
else
    echo "BPF maps directory found: $BPF_MAP_DIR"
fi

echo ""
echo "Setup completed successfully!"
echo ""
echo "Next steps:"
echo "1. Add trusted users to the '$GROUP_NAME' group:"
echo "   usermod -a -G $GROUP_NAME <username>"
echo ""
echo "2. Start the daemon:"
echo "   systemctl start $SERVICE_NAME"
echo ""
echo "3. Check daemon status:"
echo "   systemctl status $SERVICE_NAME"
echo ""
echo "4. View daemon logs:"
echo "   journalctl -u $SERVICE_NAME -f"
echo ""
echo "5. Test process hiding with user commands:"
echo "   ps aux | grep <hidden_process>"
echo ""

# Optional: Add current user to bpfusers group if not root
if [[ -n "$SUDO_USER" ]] && [[ "$SUDO_USER" != "root" ]]; then
    echo "Adding user '$SUDO_USER' to group '$GROUP_NAME'..."
    usermod -a -G "$GROUP_NAME" "$SUDO_USER"
    echo "Note: User '$SUDO_USER' needs to log out and back in for group changes to take effect"
fi

echo "Setup script completed!"
