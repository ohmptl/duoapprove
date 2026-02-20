# Duo Auto-Approver

Automatically approve Duo Mobile push requests without a phone. Runs 24/7 as a lightweight Python script.

Based on [Ruo](https://github.com/falsidge/ruo) and [Auto-2FA](https://github.com/FreshSupaSulley/Auto-2FA).

## Quick Start

### One-Line Server Setup

**Linux:**
```bash
chmod +x setup.sh && ./setup.sh
```

**Windows (PowerShell — run as admin):**
```powershell
.\setup.ps1
```

Both scripts handle venv creation, dependency install, activation, and setting up a background service (systemd on Linux, Scheduled Task on Windows).

### Manual Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run (first time — interactive setup)
python main.py

# 3. Follow the prompts to activate a device
```

## Setup Options

On first run you'll be prompted to choose one of:

| Option | When to use |
|--------|-------------|
| **1) Activate with a new code** | You're adding a new device from your Duo portal |
| **2) Import Auto-2FA export** | You already have Auto-2FA working in your browser |
| **3) Import Ruo files** | You have an existing `response.json` + `key.pem` from Ruo |

### Getting an Activation Code

1. Go to your organization's Duo device management page
2. Click **Add a new device** → **Duo Mobile** → **I have a tablet**
3. Either:
   - Scan the QR code with another QR scanner and copy the text
   - Click **Get an activation link** and email it to yourself, then open the link on your computer
4. Paste the code or URL when prompted

### Command-Line Usage

```bash
# Activate with a code directly
python main.py "CODE-BASE64HOST"

# Activate with the emailed URL
python main.py "https://m-XXXX.duosecurity.com/activate/CODE"

# Import Auto-2FA browser extension export
python main.py --import exported.json

# Adjust poll interval (default: 5 seconds)
python main.py --poll-interval 10
```

## Running 24/7

### Linux (systemd) — Recommended

The `setup.sh` script creates a systemd service automatically. To manage it:

```bash
sudo systemctl status duo-approver    # Check status
sudo systemctl restart duo-approver   # Restart
sudo systemctl stop duo-approver      # Stop
journalctl -u duo-approver -f         # View live logs
```

### Linux (manual)

```bash
nohup python main.py > /dev/null 2>&1 &
tail -f duo_approver.log
```

### Windows

```powershell
# Run in background
Start-Process python -ArgumentList "main.py" -WindowStyle Hidden

# Or just keep a terminal open
python main.py
```

## Files

| File | Purpose |
|------|---------|
| `main.py` | Main script |
| `requirements.txt` | Python dependencies |
| `setup.sh` | One-command Linux server setup |
| `setup.ps1` | One-command Windows setup |
| `duo_config.json` | Saved credentials (created after setup) |
| `duo_key.pem` | RSA private key (created after setup) |
| `duo_approver.log` | Runtime log |

## Security Notes

- `duo_config.json` and `duo_key.pem` contain your device credentials — keep them private
- This is less secure than the official Duo Mobile app
- Only use this when automated approval is acceptable for your threat model
- The device registers as a Samsung Galaxy Tab S9+ running Duo Mobile 4.87.0

## Requirements

- Python 3.10+
- `pycryptodome`
- `requests`
