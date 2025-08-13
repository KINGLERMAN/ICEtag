# ICEtag (enhanced build)

This build adds:
- Cross-platform scanner (Windows/macOS/Linux) with richer fields.
- Privacy-preserving BSSID hashing + optional raw BSSID return.
- Evidence-friendly fields: auth/encryption/radio/channel/beacon interval/WPS presence/OUI.
- Vendor OUI (first 6 hex of BSSID) stored as string; no large vendor DB needed.
- Correlation counters: first_seen/last_seen/seen_count and RSSI min/max.
- Simple CSV/JSON export routes.
- Basic views for sightings/uploads/friendly lists and correlation groups.

## Quickstart

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip wheel setuptools
pip install -r requirements.txt

# First run creates DB
python app.py

# Visit
http://127.0.0.1:5005/
```

### Windows scanning
The scanner uses `netsh wlan show networks mode=bssid` (no admin needed).

### macOS scanning
Uses: `/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s`

### Linux scanning
Attempts `nmcli dev wifi list` then `iw dev <iface> scan` as fallback (requires perms).

## Database
Default at `data/ice.db`. Use DB Browser for SQLite to inspect (GUI), or the `/export.json` & `/export.csv` routes.

## Security/Privacy
- The database stores **bssid_hash** (salted with PEPPER), not raw BSSID.
- API can optionally emit raw BSSID if `STORE_RAW_BSSID=true` for diagnostic work.
- Consider k-anonymity display rules in any public UI (not included here).
