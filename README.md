
# ICEtag v0.2 — Nearby Digital Footprints

**Goal:** Detect and log nearby digital devices (Wi‑Fi APs + LAN/IoT) with zero external dependencies. Works on Windows/macOS/Linux.

## Quickstart (Windows PowerShell)

```pwsh
cd PATH\TO\ICEtag_v0_2
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install flask

python app.py   # opens your default browser
```

## What changed

- Robust **LAN discovery**: ICMP sweep of all private subnets from `ipconfig`, ARP cache harvest, quick mDNS probe to nudge sleepy devices, vendor guess from OUI.
- Better **diagnostics**: shows subnets scanned and helpful firewall hints.
- Safe **SQLite**: creates `data/` if missing, no more "unable to open database file".
- UI polish + **auto‑open browser** on startup.

> Tip (Windows): enable *File and Printer Sharing (Echo Request – ICMPv4‑In)* for **Private** networks in Windows Defender Firewall to maximize discovery.
