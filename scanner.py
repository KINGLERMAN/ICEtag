
import os as _os, re, platform, ipaddress, subprocess, shutil, json, time
from datetime import datetime, timezone

# Tunables via environment
TIMEOUT_MS = str(int(_os.getenv("ICETAG_TIMEOUT_MS", "200")))   # per-host ping timeout (ms)
MAX_HOSTS_PER_SUBNET = int(_os.getenv("ICETAG_MAX_HOSTS", "96"))
SUBNET_LIMIT = int(_os.getenv("ICETAG_SUBNET_LIMIT", "12"))
VERBOSE = _os.getenv("ICETAG_VERBOSE", "0") == "1"
DISABLE_MDNS = _os.getenv("ICETAG_DISABLE_MDNS", "0") == "1"

def _log(msg):
    if VERBOSE:
        print(f"[ICETAG] {msg}", flush=True)

def _run(cmd, timeout=25):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=False, text=True, encoding="utf-8", timeout=timeout)
    except Exception as e:
        _log(f"cmd failed: {' '.join(cmd)} :: {e}")
        return ""

def _now_utc():
    return int(datetime.now(timezone.utc).timestamp())

def scan_wifi():
    sys = platform.system().lower()
    if "windows" in sys:
        return scan_wifi_windows()
    elif "darwin" in sys:
        return scan_wifi_macos()
    else:
        return scan_wifi_linux()

def scan_lan():
    sys = platform.system().lower()
    if "windows" in sys:
        return scan_lan_windows()
    elif "darwin" in sys:
        return scan_lan_macos()
    else:
        return scan_lan_linux()

def scan_diagnostics(wifi=None, lan=None):
    sys = platform.system().lower()
    if "windows" in sys:
        return diag_windows(wifi, lan)
    elif "darwin" in sys:
        return diag_macos(wifi, lan)
    else:
        return diag_linux(wifi, lan)

# ---------------- Wi-Fi (Windows) ----------------
def scan_wifi_windows():
    items = []
    os_name = "windows"

    cmds = [
        [ _os.path.join(_os.getenv("WINDIR","C:\\Windows"),"system32","netsh.exe"), "wlan", "show", "networks", f'interface="{_current_wifi_iface_name()}"', "mode=bssid" ],
        [ _os.path.join(_os.getenv("WINDIR","C:\\Windows"),"system32","netsh.exe"), "wlan", "show", "networks", "mode=bssid" ],
        [ _os.path.join(_os.getenv("WINDIR","C:\\Windows"),"system32","netsh.exe"), "wlan", "show", "all" ],
    ]

    out_join = ""
    for c in cmds:
        out = _run(c)
        out_join += out + "\n---\n"

    ssid_blocks = re.split(r"\bSSID\s+\d+\s*:", out_join, flags=re.I)
    ssid_names = re.findall(r"\bSSID\s+\d+\s*:\s*(.+)", out_join, flags=re.I)
    for name, block in zip(ssid_names, ssid_blocks[1:]):
        auth = _m1(r"Authentication\s*:\s*(.+)", block)
        enc = _m1(r"Encryption\s*:\s*(.+)", block)
        for bssid_block in re.split(r"BSSID\s+\d+\s*:", block)[1:]:
            bssid = _m1(r"^\s*([0-9a-f]{2}(:[0-9a-f]{2}){5})", bssid_block, flags=re.I|re.M)
            if not bssid:
                continue
            channel = _m1(r"Channel\s*:\s*(\d+)", bssid_block)
            signal = _m1(r"Signal\s*:\s*(\d+)%", bssid_block)
            items.append({
                "ssid": (name or "").strip(),
                "bssid": bssid.lower(),
                "channel": int(channel) if channel else None,
                "rssi_pct": int(signal) if signal else None,
                "auth": (auth or "").strip(),
                "encryption": (enc or "").strip(),
                "band": _band_from_channel(channel),
                "host": _hostname(),
                "ts_utc": _now_utc(),
            })

    if not items:
        iface_out = _run([_os.path.join(_os.getenv("WINDIR","C:\\Windows"),"system32","netsh.exe"), "wlan", "show", "interfaces"])
        ssid = _m1(r"SSID\s*:\s*(.+)", iface_out)
        bssid = _m1(r"AP BSSID\s*:\s*([0-9A-Fa-f:]{17})", iface_out)
        channel = _m1(r"Channel\s*:\s*(\d+)", iface_out)
        signal = _m1(r"Signal\s*:\s*(\d+)%", iface_out)
        auth = _m1(r"Authentication\s*:\s*(.+)", iface_out)
        cipher = _m1(r"Cipher\s*:\s*(.+)", iface_out)
        if ssid and bssid:
            items.append({
                "ssid": ssid.strip(),
                "bssid": bssid.lower(),
                "channel": int(channel) if channel else None,
                "rssi_pct": int(signal) if signal else None,
                "auth": (auth or "").strip(),
                "encryption": (cipher or "").strip(),
                "band": _band_from_channel(channel),
                "host": _hostname(),
                "ts_utc": _now_utc()
            })

    return {
        "count": len(items),
        "items": items,
        "os": os_name,
        "hint": "Windows sometimes hides neighbor BSSIDs. Ensure Wi‑Fi is ON, run as Admin, and try toggling Wi‑Fi."
    }

# ---------------- LAN (Windows) ----------------
def scan_lan_windows():
    _log("LAN scan start (Windows)")
    ipcfg = _run(["ipconfig","/all"])
    _log("Parsed ipconfig for private subnets")
    subnets = _private_subnets_from_ipconfig(ipcfg)
    if len(subnets) > SUBNET_LIMIT:
        _log(f"Too many subnets ({len(subnets)}); limiting to first {SUBNET_LIMIT}")
        subnets = subnets[:SUBNET_LIMIT]
    _log(f"Candidate subnets: {subnets}")

    found = {}
    phases = []
    for cidr in subnets:
        _log(f"Scanning {cidr}")
        hosts = list(ipaddress.ip_network(cidr, False).hosts())
        if len(hosts) > MAX_HOSTS_PER_SUBNET:
            hosts = hosts[:MAX_HOSTS_PER_SUBNET]
        for h in hosts:
            if VERBOSE and (int(str(h).split(".")[-1]) % 32 == 1):
                _log(f" ping {h} ...")
            _run(["ping","-n","1","-w",TIMEOUT_MS,str(h)])
        _log("Reading ARP table")
        arp = _run(["arp","-a"])
        for ip, mac in _parse_arp_windows(arp):
            if _is_private(ip):
                found[ip] = {
                    "ip": ip,
                    "mac": mac,
                    "host": _hostname(),
                    "iface": "unknown",
                    "vendor": _vendor_guess(mac),
                    "ts_utc": _now_utc()
                }
        phases.append({"cidr": cidr, "step":"icmp+arp", "found": len(found), "iface":"unknown"})

    # Optional mDNS nudge
    try:
        if DISABLE_MDNS:
            _log("mDNS probe disabled by env")
        else:
            import socket
            mdns_query = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x07_services\x04_udp\x05_local\x00" + b"\x00\x0C\x00\x01"
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.2)
            sock.sendto(mdns_query, ("224.0.0.251", 5353))
            _log("mDNS probe sent")
            sock.close()
            time.sleep(0.2)
            _log("Reading ARP after mDNS")
            arp = _run(["arp","-a"])
            for ip, mac in _parse_arp_windows(arp):
                if ip not in found and _is_private(ip):
                    found[ip] = {
                        "ip": ip, "mac": mac, "host": _hostname(),
                        "iface":"unknown", "vendor": _vendor_guess(mac), "ts_utc": _now_utc()
                    }
    except Exception as e:
        _log(f"mDNS step skipped/failed: {e}")

    items = list(found.values())
    _log(f"LAN scan done, devices: {len(items)}")
    return {"count": len(items), "items": items, "phase": phases}

def diag_windows(wifi=None, lan=None):
    hint = "Enable ICMP Echo (Private) in Windows Defender Firewall to improve discovery; some hosts ignore pings."
    interfaces = _run(["ipconfig"])
    return {
        "lan": {
            "hint": hint,
            "interfaces": interfaces,
            "phase": lan.get("phase") if lan else [],
            "ts_utc": _now_utc()
        },
        "wifi": {
            "hint": wifi.get("hint") if wifi else "",
            "os": "windows",
            "scan_cmds": ["ipconfig /all","netsh wlan show networks mode=bssid","netsh wlan show interfaces"],
            "ts_utc": _now_utc()
        }
    }

# ---------------- macOS/Linux (generic) ----------------
def scan_wifi_macos():
    out = _run(["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport","-s"])
    items = []
    for line in out.splitlines()[1:]:
        parts = re.split(r"\s{2,}", line.strip())
        if len(parts) >= 6:
            ssid, bssid, rssi, chan = parts[0], parts[1], parts[2], parts[3]
            items.append({"ssid": ssid, "bssid": bssid.lower(), "rssi": rssi, "channel": int(re.sub(r"[^0-9]","",chan) or 0)})
    return {"count": len(items), "items": items, "os":"macos"}

def scan_lan_macos():
    return _lan_from_arp_generic()

def diag_macos(wifi=None, lan=None):
    return {"lan": {"hint":"Try `ping -c 1` sweep + `arp -a` for more entries."}, "wifi":{"hint":"Use `airport -s`"}}

def scan_wifi_linux():
    out = _run(["nmcli","-f","ssid,bssid,chan,signal,security","device","wifi","list"])
    items = []
    for line in out.splitlines():
        if ":" in line or "BSSID" in line: 
            continue
        cols = [c.strip() for c in line.split()]
        if len(cols) >= 4:
            bssid = cols[1]
            chan = int(cols[2]) if cols[2].isdigit() else None
            sig = int(cols[3]) if cols[3].isdigit() else None
            items.append({"ssid": cols[0], "bssid": bssid, "channel": chan, "rssi_pct": sig})
    return {"count": len(items), "items": items, "os":"linux"}

def scan_lan_linux():
    return _lan_from_arp_generic()

def diag_linux(wifi=None, lan=None):
    return {"lan":{"hint":"Run as root for better ARP visibility."},"wifi":{"hint":"Use `nmcli device wifi list`."}}

# ---------------- helpers ----------------
def _lan_from_arp_generic():
    ranges = ["192.168.0.0/24","192.168.1.0/24","10.0.0.0/24","172.16.0.0/24"]
    found = {}
    for cidr in ranges:
        hosts = list(ipaddress.ip_network(cidr, False).hosts())[:MAX_HOSTS_PER_SUBNET]
        for h in hosts:
            _run(["ping","-c","1","-W","1",str(h)])
        arp = _run(["arp","-n"])
        for line in arp.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+.*\s+((?:[0-9a-f]{2}:){5}[0-9a-f]{2})", line, flags=re.I)
            if m:
                ip, mac = m.group(1), m.group(2).lower()
                found[ip] = {"ip": ip, "mac": mac, "host": _hostname(), "iface":"unknown", "vendor": _vendor_guess(mac), "ts_utc": _now_utc()}
    return {"count": len(found), "items": list(found.values())}

def _current_wifi_iface_name():
    out = _run(["netsh","wlan","show","interfaces"])
    m = re.search(r"Name\s*:\s*(.+)", out)
    return m.group(1).strip() if m else "Wi-Fi"

def _hostname():
    try:
        return platform.node()
    except Exception:
        return "unknown"

def _m1(pat, txt, flags=0):
    m = re.search(pat, txt, flags)
    return m.group(1).strip() if m else None

def _band_from_channel(ch):
    try:
        c = int(ch)
    except Exception:
        return None
    if 1 <= c <= 14: return "2.4GHz"
    if 32 <= c <= 177: return "5GHz/6GHz"
    return None

def _vendor_guess(mac):
    if not mac: return None
    oui = mac[:8].upper().replace("-",":")
    vendors = {
        "F0:09:0D":"Ubiquiti / UniFi",
        "00:50:56":"VMware",
        "D8:EB:46":"Xiaomi/Beijing-Tianmi?",
        "28:C5:D2":"Samsung?",
        "20:9B:E6":"AzureWave?",
    }
    return vendors.get(oui)

def _parse_arp_windows(arp_out):
    for line in arp_out.splitlines():
        m = re.search(r"\s*(\d+\.\d+\.\d+\.\d+)\s+((?:[0-9a-f]{2}-){5}[0-9a-f]{2})\s+(\w+)", line, flags=re.I)
        if m:
            ip = m.group(1)
            mac = m.group(2).replace("-",":").lower()
            yield ip, mac

def _is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def _private_subnets_from_ipconfig(txt):
    subnets = set()
    adapters = re.split(r"\r?\n\r?\n", txt)
    for ad in adapters:
        ip = _m1(r"IPv4 Address.*?:\s*([0-9\.]+)", ad)
        mask = _m1(r"Subnet Mask.*?:\s*([0-9\.]+)", ad)
        if ip and mask:
            try:
                net = ipaddress.IPv4Network((ip, mask), strict=False)
                if net.network_address.is_private:
                    if net.prefixlen < 24:
                        base = ipaddress.ip_network(str(net), False)
                        for sub in base.subnets(new_prefix=24):
                            subnets.add(str(sub))
                    else:
                        subnets.add(str(net))
            except Exception:
                pass
    # Helpful common ranges seen in VM/VPN stacks:
    common = ["192.168.56.0/24","192.168.201.0/24","192.168.10.0/24","172.18.160.0/24","10.5.0.0/24","192.168.0.0/24"]
    for cidr in common:
        subnets.add(cidr)
    return sorted(subnets)
