def group_by_ssid_bssid(rows):
    groups = {}
    for r in rows:
        key = (r.get("ssid"), r.get("bssid_hash"))
        groups.setdefault(key, []).append(r)
    return groups
