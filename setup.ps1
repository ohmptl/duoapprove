# ─────────────────────────────────────────────────────────────
# Duo Auto-Approver — Windows Setup Script
#
# Usage:
#   .\setup.ps1
#
# What it does:
#   1. Checks for Python 3.10+
#   2. Creates a venv and installs dependencies
#   3. Runs the activation wizard (if no credentials exist)
#   4. Optionally creates a scheduled task for 24/7 operation
# ─────────────────────────────────────────────────────────────

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$VenvDir = Join-Path $ScriptDir ".venv"
$TaskName = "DuoAutoApprover"

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Duo Auto-Approver — Windows Setup"       -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# ── 1. Find Python ────────────────────────────────────────────
$Python = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python (\d+)\.(\d+)") {
            $major = [int]$Matches[1]
            $minor = [int]$Matches[2]
            if ($major -ge 3 -and $minor -ge 10) {
                $Python = $cmd
                Write-Host "[+] Found $cmd ($ver)" -ForegroundColor Green
                break
            }
        }
    } catch { }
}

if (-not $Python) {
    Write-Host "[-] Python 3.10+ not found." -ForegroundColor Red
    Write-Host "    Download from https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "    Make sure to check 'Add Python to PATH' during install." -ForegroundColor Yellow
    exit 1
}

# ── 2. Create venv & install dependencies ─────────────────────
Write-Host ""
if (-not (Test-Path $VenvDir)) {
    Write-Host "[*] Creating virtual environment..."
    & $Python -m venv $VenvDir
}

$ActivateScript = Join-Path $VenvDir "Scripts\Activate.ps1"
if (-not (Test-Path $ActivateScript)) {
    Write-Host "[-] Venv activation script not found at $ActivateScript" -ForegroundColor Red
    exit 1
}

& $ActivateScript

Write-Host "[*] Installing dependencies..."
$ErrorActionPreference = "Continue"
pip install --quiet --upgrade pip 2>$null
pip install --quiet -r (Join-Path $ScriptDir "requirements.txt") 2>$null
$ErrorActionPreference = "Stop"
Write-Host "[+] Dependencies installed" -ForegroundColor Green

# ── 3. Run activation if no config exists ─────────────────────
Write-Host ""
$ConfigFile = Join-Path $ScriptDir "duo_config.json"
$KeyFile = Join-Path $ScriptDir "duo_key.pem"
$MainScript = Join-Path $ScriptDir "main.py"

if (-not (Test-Path $ConfigFile) -or -not (Test-Path $KeyFile)) {
    Write-Host "[*] No credentials found — running activation wizard..."
    Write-Host ""
    python $MainScript

    if (-not (Test-Path $ConfigFile)) {
        Write-Host ""
        Write-Host "[-] Activation did not complete. Re-run this script to try again." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[+] Credentials already exist (duo_config.json + duo_key.pem)" -ForegroundColor Green
}

# ── 4. Offer to create a scheduled task ───────────────────────
Write-Host ""
Write-Host "─── Run as Background Service ───" -ForegroundColor Cyan
Write-Host ""
Write-Host "Would you like to create a Windows Scheduled Task to run"
Write-Host "the auto-approver at startup and keep it running 24/7?"
Write-Host ""
$choice = Read-Host "Create scheduled task? [y/N]"

if ($choice -match "^[yY]") {
    $PythonExe = Join-Path $VenvDir "Scripts\python.exe"

    # Remove existing task if present
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "[*] Removed existing task" -ForegroundColor Yellow
    }

    $Action = New-ScheduledTaskAction `
        -Execute $PythonExe `
        -Argument "`"$MainScript`"" `
        -WorkingDirectory $ScriptDir

    $Trigger = New-ScheduledTaskTrigger -AtLogon

    $Settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -RestartCount 9999 `
        -ExecutionTimeLimit (New-TimeSpan -Days 9999)

    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $Action `
        -Trigger $Trigger `
        -Settings $Settings `
        -Description "Duo Auto-Approver — auto-approve Duo push requests" `
        -RunLevel Highest | Out-Null

    # Start it now
    Start-ScheduledTask -TaskName $TaskName

    Write-Host "[+] Scheduled task '$TaskName' created and started" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Status:   Get-ScheduledTask -TaskName $TaskName"
    Write-Host "  Stop:     Stop-ScheduledTask -TaskName $TaskName"
    Write-Host "  Remove:   Unregister-ScheduledTask -TaskName $TaskName"
    Write-Host "  Logs:     Get-Content `"$(Join-Path $ScriptDir 'duo_approver.log')`" -Tail 50 -Wait"
} else {
    Write-Host ""
    Write-Host "Skipped. To run manually:"
    Write-Host ""
    Write-Host "  cd $ScriptDir" -ForegroundColor Yellow
    Write-Host "  .\.venv\Scripts\Activate.ps1" -ForegroundColor Yellow
    Write-Host "  python main.py" -ForegroundColor Yellow
}

# ── Done ──────────────────────────────────────────────────────
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Setup Complete!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
