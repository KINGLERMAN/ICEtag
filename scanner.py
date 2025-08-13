# scanner.py — robust cross‑platform Wi‑Fi scanner (v0.1.7)
# - Windows: interface quoting, encoding fallback, multi‑iface loop
#   + primary parser for `netsh wlan show networks mode=bssid`
#   + fallback parser for `netsh wlan show all`
#   + final fallback: parse currently-connected AP from `netsh wlan show interfaces`
# - macOS: airport -s
# - Linux: nmcli, fallback to iw
# - Per‑item time + location stamping for later correlation
#
# Returns: (results: list[dict], diag: dict)

import os
import json
import platform
import subprocess
import re
import locale
import shutil
from datetime import datetime, timezone

# ---------------- helpers ----------------

def _run(cmd, timeout=30):
    """Run a command and return text. Try utf-8, then system encoding, then ignore errors."""
    try:
        return subprocess.check_output(
            cmd, stderr=subprocess.STDOUT, shell=False,
            text=True, encoding="utf-8", timeout=timeout
        )
    except Exception:
        try:
            enc = locale.getpreferredencoding(False) or "cp1252"
            return subprocess.check_output(
                cmd, stderr=subprocess.STDOUT, shell=False,
                text=True, encoding=enc, timeout=timeout
            )
        except Exception:
            try:
                raw = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=False, timeout=timeout)
                return raw.decode("utf-8", errors="ignore")
            except Exception:
                return ""

def _pct_to_rssi_dbm(pct):
    try:
        p = int(pct); return int(round(p/2 - 100))
    except Exception:
        return None

def _channel_to_band(ch):
    try:
        c = int(ch) if ch is not None else None
    except Exception:
        return None
    if c is None: return None
    if 1 <= c <= 14: return "2.4GHz"
    if 32 <= c <= 173: return "5GHz"
    if c >= 180: return "6GHz"
    return None

def _now_meta():
    """UTC timestamp + local offset minutes (for cross‑TZ merges)."""
    dt = datetime.now(timezone.utc)
    ts_utc = int(dt.timestamp())
    local = datetime.now().astimezone()
    offset_min = int(local.utcoffset().total_seconds() // 60) if local.utcoffset() else 0
    return ts_utc, offset_min

# ---------- location provider (file/env; no network needed) ----------

def _load_location():
    """
    Return (lat, lon, accuracy_m, source) or (None, None, None, None).
    Priority:
      1) env vars: ICETAG_LAT, ICETAG_LON, ICETAG_LOC_ACC, ICETAG_LOC_SOURCE
      2) geo.json in ./ or ./config/  -> {lat, lon, accuracy_m, source}
    """
    lat_env = os.getenv("ICETAG_LAT")
    lon_env = os.getenv("ICETAG_LON")
    if lat_env and lon_env:
        try:
            lat = float(lat_env); lon = float(lon_env)
            acc = float(os.getenv("ICETAG_LOC_ACC") or "0") or None
            src = os.getenv("ICETAG_LOC_SOURCE") or "env"
            return lat, lon, acc, src
        except Exception:
            pass

    candidates = [
        os.path.join(os.getcwd(), "geo.json"),
        os.path.join(os.getcwd(), "config", "geo.json"),
    ]
    for p in candidates:
        try:
            if os.path.exists(p):
                data = json.load(open(p, "r", encoding="utf-8"))
                lat = float(data.get("lat"))
                lon = float(data.get("lon"))
                acc = data.get("accuracy_m")
                acc = float(acc) if acc is not None else None
                src = data.get("source") or "geo.json"
                return lat, lon, acc, src
        except Exception:
            continue

    return None, None, None, None

def _stamp_common(entry, ts_utc, tz_offset_min, lat, lon, acc_m, loc_source):
    """Attach time & location to a single result entry."""
    entry["ts_utc"] = ts_utc
    entry["tz_offset_min"] = tz_offset_min
    entry["lat"] = lat
    entry["lon"] = lon
    entry["loc_accuracy_m"] = acc_m
    entry["loc_source"] = loc_source
    entry["host"] = platform.node()
    return entry

def scan():
    sys = platform.system().lower()
    if "windows" in sys:
        return _scan_windows_netsh()
    if "darwin" in sys:
        return _scan_macos_airport()
    return _scan_linux()

# ---------------- Windows ----------------

_NETSH = shutil.which("netsh") or "netsh"

def _win_list_interfaces():
    out = _run([_NETSH, "wlan", "show", "interfaces"])
    names = []
    for m in re.finditer(r"^\s*Name\s*:\s*(.+)$", out, re.I | re.M):
        names.append(m.group(1).strip())
    if not names:
        for m in re.finditer(r"^\s*Interface name\s*:\s*(.+)$", out, re.I | re.M):
            names.append(m.group(1).strip())
    # de-dupe preserve order
    seen, ordered = set(), []
    for n in names:
        if n not in seen:
            seen.add(n); ordered.append(n)
    return ordered, out

def _parse_windows_blocks(txt):
    """Primary parser for `netsh wlan show networks mode=bssid` (locale-agnostic)."""
    items = []
    sections = re.split(r"(?=^\s*SSID\s*\d+\s*:\s*)", txt, flags=re.I | re.M)
    for sec in sections:
        m_ssid = re.search(r"^\s*SSID\s*\d+\s*:\s*(.+)$", sec, flags=re.I | re.M)
        if not m_ssid:
            continue
        ssid = (m_ssid.group(1) or "").strip() or None

        # block-level fields
        auth  = (re.search(r"^\s*Authentication\s*:\s*(.+)$", sec, re.I | re.M) or None)
        enc   = (re.search(r"^\s*Encryption\s*:\s*(.+)$", sec, re.I | re.M) or None)
        radio = (re.search(r"^\s*Radio type\s*:\s*(.+)$", sec, re.I | re.M) or None)
        chan  = (re.search(r"^\s*Channel\s*:\s*([0-9]+)", sec, re.I | re.M) or None)

        auth  = auth.group(1).strip() if auth else None
        enc   = enc.group(1).strip() if enc else None
        radio = radio.group(1).strip() if radio else None
        ch    = int(chan.group(1)) if chan else None

        last = None
        for line in sec.splitlines():
            m_mac = re.search(r"([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})", line)
            if m_mac:
                mac = m_mac.group(1).lower()
                items.append({
                    "ssid": ssid,
                    "bssid": mac,
                    "bssid_oui": mac.replace(":", "")[:6].upper(),
                    "channel": ch,
                    "band": _channel_to_band(ch),
                    "rssi": None,
                    "rssi_pct": None,
                    "auth": auth,
                    "encryption": enc,
                    "radio": radio,
                    "beacon_interval": None,
                    "has_wps": None,
                    "scanner_platform": "Windows",
                })
                last = items[-1]
                continue
            if last:
                m_sig = re.search(r"Signal\s*:\s*(\d+)\s*%", line, re.I)
                if m_sig:
                    pct = int(m_sig.group(1))
                    last["rssi_pct"] = pct
                    last["rssi"] = _pct_to_rssi_dbm(pct)
                    continue
                if re.search(r"\bWPS\b\s*:", line, re.I):
                    last["has_wps"] = True
    return items

def _parse_windows_show_all(txt):
    """Fallback parser for `netsh wlan show all`."""
    items = []
    blocks = re.split(r"(?=^\s*SSID\s*\d+\s*:\s*)", txt, flags=re.I | re.M)
    for blk in blocks:
        m_ssid = re.search(r"^\s*SSID\s*\d+\s*:\s*(.+)$", blk, flags=re.I | re.M)
        if not m_ssid:
            continue
        ssid = (m_ssid.group(1) or "").strip() or None
        chan  = (re.search(r"^\s*Channel\s*:\s*([0-9]+)", blk, re.I | re.M) or None)
        ch    = int(chan.group(1)) if chan else None
        auth  = (re.search(r"^\s*Authentication\s*:\s*(.+)$", blk, re.I | re.M) or None)
        enc   = (re.search(r"^\s*Encryption\s*:\s*(.+)$", blk, re.I | re.M) or None)
        auth  = auth.group(1).strip() if auth else None
        enc   = enc.group(1).strip() if enc else None

        for m in re.finditer(r"BSSID\s*\d+\s*:\s*([0-9A-Fa-f:]{17})", blk):
            mac = m.group(1).lower()
            tail = blk[m.end(): m.end()+200]
            m_sig = re.search(r"Signal\s*:\s*(\d+)\s*%", tail, re.I)
            pct = int(m_sig.group(1)) if m_sig else None
            items.append({
                "ssid": ssid,
                "bssid": mac,
                "bssid_oui": mac.replace(":", "")[:6].upper(),
                "channel": ch,
                "band": _channel_to_band(ch),
                "rssi": _pct_to_rssi_dbm(pct) if pct is not None else None,
                "rssi_pct": pct,
                "auth": auth,
                "encryption": enc,
                "radio": None,
                "beacon_interval": None,
                "has_wps": None,
                "scanner_platform": "Windows(show all)",
            })
    return items

def _parse_connected_from_interfaces(txt):
    """Last‑ditch: pull currently‑connected AP from `netsh wlan show interfaces`."""
    m_bssid = re.search(r"^\s*AP BSSID\s*:\s*([0-9A-Fa-f:]{17})", txt, re.I | re.M)
    if not m_bssid:
        return None
    bssid = m_bssid.group(1).lower()
    m_ssid = re.search(r"^\s*SSID\s*:\s*(.+)$", txt, re.I | re.M)
    ssid = m_ssid.group(1).strip() if m_ssid else None
    m_ch = re.search(r"^\s*Channel\s*:\s*(\d+)", txt, re.I | re.M)
    ch = int(m_ch.group(1)) if m_ch else None
    m_auth = re.search(r"^\s*Authentication\s*:\s*(.+)$", txt, re.I | re.M)
    auth = m_auth.group(1).strip() if m_auth else None
    m_enc = re.search(r"^\s*Cipher\s*:\s*(.+)$", txt, re.I | re.M)
    enc = m_enc.group(1).strip() if m_enc else None
    m_sig = re.search(r"^\s*Signal\s*:\s*(\d+)\s*%", txt, re.I | re.M)
    pct = int(m_sig.group(1)) if m_sig else None
    return {
        "ssid": ssid,
        "bssid": bssid,
        "bssid_oui": bssid.replace(":", "")[:6].upper(),
        "channel": ch,
        "band": _channel_to_band(ch),
        "rssi_pct": pct,
        "rssi": _pct_to_rssi_dbm(pct) if pct is not None else None,
        "auth": auth,
        "encryption": enc,
        "radio": None,
        "beacon_interval": None,
        "has_wps": None,
        "scanner_platform": "Windows(interfaces)",
    }

def _scan_windows_netsh():
    ts_utc, tz_offset_min = _now_meta()
    lat, lon, acc_m, loc_src = _load_location()

    diag = {
        "os":"windows",
        "ts_utc": ts_utc,
        "tz_offset_min": tz_offset_min,
        "loc": {"lat": lat, "lon": lon, "accuracy_m": acc_m, "source": loc_src},
        "hint": ("If you still see 0 items: ensure Wi‑Fi is ON, run once as Admin, and "
                 "verify 'WLAN AutoConfig' (WlanSvc) is running. Toggle Wi‑Fi off/on and retry."),
    }

    interfaces, iface_block = _win_list_interfaces()
    diag["interfaces"] = iface_block

    tried_cmds, heads, all_items = [], [], []

    # 1) Try each interface explicitly (quoted, then unquoted), parsing 'networks mode=bssid'
    if interfaces:
        for name in interfaces:
            cmd_q = [_NETSH, "wlan", "show", "networks", f'interface="{name}"', "mode=bssid"]
            tried_cmds.append(" ".join(cmd_q))
            out = _run(cmd_q).strip()
            if not out:
                cmd_u = [_NETSH, "wlan", "show", "networks", f"interface={name}", "mode=bssid"]
                tried_cmds.append(" ".join(cmd_u))
                out = _run(cmd_u).strip()
            if out:
                heads.append("\n".join(out.splitlines()[:80]))
                all_items.extend(_parse_windows_blocks(out))

    # 2) Global 'networks mode=bssid'
    if not all_items:
        cmd = [_NETSH, "wlan", "show", "networks", "mode=bssid"]
        tried_cmds.append(" ".join(cmd))
        out = _run(cmd).strip()
        if out:
            heads.append("\n".join(out.splitlines()[:80]))
            all_items.extend(_parse_windows_blocks(out))

    # 3) Fallback: `netsh wlan show all`
    if not all_items:
        cmd = [_NETSH, "wlan", "show", "all"]
        tried_cmds.append(" ".join(cmd))
        out = _run(cmd, timeout=45).strip()
        if out:
            heads.append("\n".join(out.splitlines()[:120]))
            all_items.extend(_parse_windows_show_all(out))

    # dedupe
    uniq = {}
    for it in all_items:
        uniq[(it["bssid"], it.get("ssid"))] = it
    results = list(uniq.values())

    # 4) Final fallback: record the connected AP from the interfaces output
    if not results and iface_block:
        one = _parse_connected_from_interfaces(iface_block)
        if one:
            _stamp_common(one, ts_utc, tz_offset_min, lat, lon, acc_m, loc_src)
            results = [one]
            diag["note"] = "Neighbors hidden by OS; recorded connected AP from interfaces."

    # stamp time/location on every item
    for it in results:
        _stamp_common(it, ts_utc, tz_offset_min, lat, lon, acc_m, loc_src)

    diag["scan_cmds"] = tried_cmds
    diag["scan_out_head"] = "\n\n---\n".join(heads)

    if not results and not heads:
        diag["hint"] = ("netsh produced no output. Check adapter/driver install and ensure Wi‑Fi is enabled.")

    return results, diag

# ---------------- macOS ----------------

def _scan_macos_airport():
    ts_utc, tz_offset_min = _now_meta()
    lat, lon, acc_m, loc_src = _load_location()

    diag = {
        "os":"macos",
        "ts_utc": ts_utc,
        "tz_offset_min": tz_offset_min,
        "loc": {"lat": lat, "lon": lon, "accuracy_m": acc_m, "source": loc_src},
    }

    airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    out = _run([airport, "-s"])
    diag["scan_out_head"] = "\n".join(out.splitlines()[:40])
    results = []
    if not out.strip():
        diag["hint"] = "No output from airport -s; ensure Wi‑Fi is enabled."
        return results, diag
    for line in out.splitlines()[1:]:
        s = line.rstrip()
        if not s: continue
        m_bssid = re.search(r"([0-9A-Fa-f:]{17})", s)
        if not m_bssid: continue
        bssid = m_bssid.group(1).lower()
        ssid = s[:m_bssid.start()].strip()
        tail = s[m_bssid.end():]
        m_rssi = re.search(r"\s(-?\d{1,3})\s", tail)
        rssi = int(m_rssi.group(1)) if m_rssi else None
        m_ch = re.search(r"\s-?\d+\s+(\d+)", tail)
        channel = int(m_ch.group(1)) if m_ch else None
        security = s.split()[-1] if s.split() else None
        entry = {
            "ssid": ssid or None,
            "bssid": bssid,
            "bssid_oui": bssid.replace(":", "")[:6].upper(),
            "channel": channel,
            "band": _channel_to_band(channel),
            "rssi": rssi,
            "rssi_pct": None,
            "auth": security,
            "encryption": None,
            "radio": None,
            "beacon_interval": None,
            "has_wps": None,
            "scanner_platform": "macOS",
        }
        results.append(_stamp_common(entry, ts_utc, tz_offset_min, lat, lon, acc_m, loc_src))
    return results, diag

# ---------------- Linux ----------------

def _scan_linux():
    ts_utc, tz_offset_min = _now_meta()
    lat, lon, acc_m, loc_src = _load_location()

    diag = {
        "os":"linux",
        "ts_utc": ts_utc,
        "tz_offset_min": tz_offset_min,
        "loc": {"lat": lat, "lon": lon, "accuracy_m": acc_m, "source": loc_src},
    }

    out = _run(["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi", "list"])
    if out.strip():
        diag["scan_cmd"] = "nmcli -t -f SSID,BSSID,CHAN,SIGNAL,SECURITY dev wifi list"
        diag["scan_out_head"] = "\n".join(out.splitlines()[:40])
        results = []
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) < 5: continue
            ssid, bssid, chan, sig, sec = parts[:5]
            bssid = (bssid or "").lower()
            rssi = _pct_to_rssi_dbm(sig) if sig else None
            try: ch = int(chan) if chan else None
            except Exception: ch = None
            entry = {
                "ssid": ssid or None,
                "bssid": bssid or None,
                "bssid_oui": bssid.replace(":", "")[:6].upper() if bssid else None,
                "channel": ch,
                "band": _channel_to_band(ch),
                "rssi": rssi,
                "rssi_pct": int(sig) if sig else None,
                "auth": sec or None,
                "encryption": None,
                "radio": None,
                "beacon_interval": None,
                "has_wps": None,
                "scanner_platform": "Linux(nmcli)",
            }
            results.append(_stamp_common(entry, ts_utc, tz_offset_min, lat, lon, acc_m, loc_src))
        if results:
            return results, diag
    else:
        diag["nmcli_note"] = "nmcli returned no data; falling back to iw."

    devs = _run(["iw", "dev"])
    diag["iw_dev"] = "\n".join(devs.splitlines()[:60])
    m = re.search(r"Interface\s+(\S+)", devs)
    if not m:
        diag["hint"] = "No wireless interface found via 'iw dev'."
        return [], diag
    iface = m.group(1)
    out = _run(["iw", "dev", iface, "scan"], timeout=45)
    diag["scan_cmd"] = f"iw dev {iface} scan"
    diag["scan_out_head"] = "\n".join(out.splitlines()[:60])
    if not out.strip():
        diag["hint"] = "Empty output from iw scan (may require sudo)."
        return [], diag

    results = []
    current = None
    for raw in out.splitlines():
        line = raw.strip()
        if "BSS " in line and re.search(r"BSS\s+([0-9A-Fa-f:]{17})", line):
            if current:
                results.append(_stamp_common(current, ts_utc, tz_offset_min, lat, lon, acc_m, loc_src))
            bssid = re.search(r"BSS\s+([0-9A-Fa-f:]{17})", line).group(1).lower()
            current = {"ssid": None, "bssid": bssid,
                "bssid_oui": bssid.replace(":", "")[:6].upper(),
                "channel": None, "band": None,
                "rssi": None, "rssi_pct": None,
                "auth": None, "encryption": None, "radio": None,
                "beacon_interval": None, "has_wps": None,
                "scanner_platform": "Linux(iw)"}
            continue
        if current is None: continue
        if line.startswith("SSID:"): current["ssid"] = line.split("SSID:",1)[1].strip() or None; continue
        if "signal:" in line:
            m_s = re.search(r"signal:\s*(-?\d+(\.\d+)?)", line)
            if m_s:
                try: current["rssi"] = int(float(m_s.group(1)))
                except Exception: pass
            continue
        if "DS Parameter set: channel" in line or "primary channel" in line:
            m_c = re.search(r"channel\s+(\d+)", line) or re.search(r"primary channel:\s*(\d+)", line)
            if m_c:
                ch = int(m_c.group(1)); current["channel"] = ch; current["band"] = _channel_to_band(ch)
            continue
        if "beacon interval" in line:
            m_bi = re.search(r"beacon interval\s+(\d+)", line)
            if m_bi: current["beacon_interval"] = int(m_bi.group(1)); continue
        if "WPS:" in line: current["has_wps"] = True; continue
        if line.startswith("HT capabilities") or "VHT" in line or "HE" in line: current["radio"] = "802.11"; continue
        if "RSN:" in line or "WPA:" in line: current["auth"] = "WPA/RSN"; continue
    if current:
        results.append(_stamp_common(current, ts_utc, tz_offset_min, lat, lon, acc_m, loc_src))
    return results, diag
