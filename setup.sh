#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Duo Auto-Approver — One-line server setup
# 
# Usage:
#   chmod +x setup.sh && ./setup.sh
#
# What it does:
#   1. Installs Python 3 + pip if missing
#   2. Creates a venv and installs dependencies
#   3. Runs the activation wizard
#   4. Creates a systemd service for 24/7 operation
# ─────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
SERVICE_NAME="duo-approver"
PYTHON=""

echo ""
echo "=========================================="
echo "  Duo Auto-Approver — Server Setup"
echo "=========================================="
echo ""

# ── 1. Find or install Python ─────────────────────────────────
find_python() {
    for cmd in python3 python; do
        if command -v "$cmd" &>/dev/null; then
            local ver
            ver=$("$cmd" --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
            local major minor
            major=$(echo "$ver" | cut -d. -f1)
            minor=$(echo "$ver" | cut -d. -f2)
            if [ "$major" -ge 3 ] && [ "$minor" -ge 10 ]; then
                PYTHON="$cmd"
                return 0
            fi
        fi
    done
    return 1
}

if find_python; then
    echo "[+] Found $PYTHON ($($PYTHON --version))"
else
    echo "[*] Python 3.10+ not found. Installing..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y -qq python3 python3-pip python3-venv
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y python3 python3-pip
    elif command -v yum &>/dev/null; then
        sudo yum install -y python3 python3-pip
    elif command -v pacman &>/dev/null; then
        sudo pacman -S --noconfirm python python-pip
    else
        echo "[-] Could not auto-install Python. Install Python 3.10+ manually."
        exit 1
    fi
    if ! find_python; then
        echo "[-] Python install succeeded but 3.10+ not found."
        exit 1
    fi
    echo "[+] Installed $PYTHON ($($PYTHON --version))"
fi

# ── 2. Create venv & install dependencies ─────────────────────
echo ""
if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Creating virtual environment..."
    $PYTHON -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"
echo "[*] Installing dependencies..."
pip install --quiet --upgrade pip
pip install --quiet -r "$SCRIPT_DIR/requirements.txt"
echo "[+] Dependencies installed"

# ── 3. Run activation if no config exists ─────────────────────
echo ""
if [ ! -f "$SCRIPT_DIR/duo_config.json" ] || [ ! -f "$SCRIPT_DIR/duo_key.pem" ]; then
    echo "[*] No credentials found — running activation wizard..."
    echo ""
    python "$SCRIPT_DIR/main.py"
    
    # Check if activation succeeded
    if [ ! -f "$SCRIPT_DIR/duo_config.json" ]; then
        echo ""
        echo "[-] Activation did not complete. Re-run this script to try again."
        exit 1
    fi
else
    echo "[+] Credentials already exist (duo_config.json + duo_key.pem)"
fi

# ── 4. Create systemd service ─────────────────────────────────
echo ""
echo "[*] Setting up systemd service..."

SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
PYTHON_BIN="$VENV_DIR/bin/python"

sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=Duo Auto-Approver
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$SCRIPT_DIR
ExecStart=$PYTHON_BIN $SCRIPT_DIR/main.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME"
sudo systemctl restart "$SERVICE_NAME"

echo "[+] Service '$SERVICE_NAME' created and started"
echo ""

# ── 5. Show status ────────────────────────────────────────────
echo "=========================================="
echo "  Setup Complete!"
echo "=========================================="
echo ""
echo "  Service:  sudo systemctl status $SERVICE_NAME"
echo "  Logs:     journalctl -u $SERVICE_NAME -f"
echo "  Stop:     sudo systemctl stop $SERVICE_NAME"
echo "  Restart:  sudo systemctl restart $SERVICE_NAME"
echo ""

sudo systemctl status "$SERVICE_NAME" --no-pager || true
