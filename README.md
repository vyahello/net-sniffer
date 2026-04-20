# Network Sniffer

Single-file network activity monitor built with Scapy. It prints live DNS, HTTP, and TCP/443 activity, tracks per-host statistics, and writes session logs plus a JSON report when you stop it with `Ctrl+C`.

> **Use only on networks and devices you own or are explicitly authorized to test.** Packet capture can expose sensitive traffic and may be illegal without consent.

## What the script does

From the current source:

- captures packets from a selected interface with Scapy
- logs DNS lookups, HTTP requests, and basic HTTPS/TLS connection events
- tracks per-host byte counts and destination ports
- looks for credential-like strings in HTTP payloads
- saves logs and a timestamped JSON report on shutdown

## Log locations

The script now stores logs in a platform-native directory:

| Platform | Log directory |
| --- | --- |
| Linux | `/var/log/wifi_monitor` when run as root |
| macOS | `~/Library/Logs/wifi_monitor` for the account running the script |
| Windows | `%LOCALAPPDATA%\wifi_monitor` |

Expected files:

- `monitor.log`
- `dns.log`
- `http.log`
- `credentials.log`
- `report_YYYYMMDD_HHMMSS.json`

On macOS, running with `sudo` usually means logs end up under `/var/root/Library/Logs/wifi_monitor`.

## Requirements

- Python 3.9+
- elevated privileges for packet capture
- one active network interface
- platform capture backend:
  - Linux/macOS: libpcap-compatible capture support
  - Windows: [Npcap](https://npcap.com/) installed

## Install

### Linux

1. Install system packages:

   **Debian/Ubuntu**
   ```bash
   sudo apt update
   sudo apt install -y python3 python3-venv python3-pip libpcap-dev
   ```

   **Fedora**
   ```bash
   sudo dnf install -y python3 python3-pip libpcap-devel
   ```

   **Arch**
   ```bash
   sudo pacman -Sy --needed python python-pip libpcap
   ```

2. Create a virtual environment and install Python dependencies:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

### macOS

1. Install Python if needed:

   ```bash
   brew install python
   ```

2. Create a virtual environment and install dependencies:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

### Windows

1. Install:
   - Python 3 from https://www.python.org/downloads/windows/
   - Npcap from https://npcap.com/ with **WinPcap API-compatible mode** enabled

2. In **PowerShell (Run as Administrator)**:

   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

## Run

### Linux

```bash
source .venv/bin/activate
sudo .venv/bin/python sniffer.py
```

### macOS

```bash
source .venv/bin/activate
sudo .venv/bin/python sniffer.py
```

### Windows

Run **PowerShell as Administrator**:

```powershell
.\.venv\Scripts\Activate.ps1
python .\sniffer.py
```

When the script starts, it:

1. prints the log directory
2. shows detected interfaces
3. prompts for the interface to monitor
4. starts live capture until you press `Ctrl+C`

If the suggested default is wrong, enter another interface name from the detected list.

## Usage notes

- Common Linux interfaces: `wlan0`, `wlp2s0`, `eth0`, `enp3s0`
- Common macOS interfaces: `en0`, `en1`
- Windows interface names vary; use the names printed by the script
- HTTPS output is limited to connection-level visibility; the script does not decrypt TLS
- Stopping with `Ctrl+C` prints summary statistics and writes a JSON report

## Troubleshooting

- **"This script requires root/Administrator privileges"**  
  Re-run the command in an elevated terminal.

- **No packets appear**  
  Verify the selected interface is active and actually carrying traffic.

- **Windows capture fails**  
  Confirm Npcap is installed and the terminal is running as Administrator.

- **Permission errors writing logs**  
  Check the printed log directory and ensure the current user can write there.
