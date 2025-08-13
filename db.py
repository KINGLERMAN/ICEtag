import os, sqlite3
from datetime import datetime
from flask import g
from dotenv import load_dotenv

load_dotenv()
DB_PATH = os.getenv("DB_PATH", "data/ice.db")

def _ensure_parent_dir(path: str):
    parent = os.path.abspath(os.path.dirname(path))
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)

def connect():
    if "db_conn" not in g:
        _ensure_parent_dir(DB_PATH)
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db_conn = conn
    return g.db_conn

def close_conn(e=None):
    conn = g.pop("db_conn", None)
    if conn is not None:
        conn.close()

def init_db():
    _ensure_parent_dir(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # sightings table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS sightings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ssid TEXT,
        bssid_hash TEXT,
        channel INTEGER,
        rssi INTEGER,
        vendor_oui TEXT,
        auth TEXT,
        encryption TEXT,
        radio TEXT,
        beacon_interval INTEGER,
        has_wps INTEGER,
        scanner_platform TEXT,
        app_version TEXT,
        first_seen TEXT,
        last_seen TEXT,
        seen_count INTEGER DEFAULT 1,
        rssi_min INTEGER,
        rssi_max INTEGER
    )""")

    # friendly list
    cur.execute("""
    CREATE TABLE IF NOT EXISTS friendly (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ssid TEXT UNIQUE,
        added_at TEXT DEFAULT (datetime('now'))
    )""")

    # uploads log
    cur.execute("""
    CREATE TABLE IF NOT EXISTS uploads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        uploaded_at TEXT DEFAULT (datetime('now'))
    )""")

    conn.commit()
    conn.close()

def _now():
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"

def _merge_sighting(conn, data):
    # Merge by a few stable fields; tweak if you want stricter/looser merges.
    cur = conn.cursor()
    cur.execute("""
        SELECT id, seen_count, rssi_min, rssi_max FROM sightings
        WHERE ssid = ? AND bssid_hash = ? AND IFNULL(auth,'') = IFNULL(?, '')
          AND IFNULL(encryption,'') = IFNULL(?, '')
          AND IFNULL(radio,'') = IFNULL(?, '')
          AND IFNULL(vendor_oui,'') = IFNULL(?, '')
    """, (data.get("ssid"), data.get("bssid_hash"), data.get("auth"),
          data.get("encryption"), data.get("radio"), data.get("vendor_oui")))
    row = cur.fetchone()
    if row:
        sid, seen_count, rmin, rmax = row["id"], row["seen_count"], row["rssi_min"], row["rssi_max"]
        new_min = data.get("rssi") if rmin is None else min(rmin, data.get("rssi"))
        new_max = data.get("rssi") if rmax is None else max(rmax, data.get("rssi"))
        cur.execute("""
            UPDATE sightings SET
                last_seen = ?,
                seen_count = ?,
                rssi_min = ?,
                rssi_max = ?,
                channel = ?
            WHERE id = ?
        """, (_now(), seen_count + 1, new_min, new_max, data.get("channel"), sid))
        conn.commit()
        return sid
    else:
        cur.execute("""
            INSERT INTO sightings (
                ssid, bssid_hash, channel, rssi, vendor_oui, auth, encryption, radio,
                beacon_interval, has_wps, scanner_platform, app_version,
                first_seen, last_seen, seen_count, rssi_min, rssi_max
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            data.get("ssid"), data.get("bssid_hash"), data.get("channel"), data.get("rssi"),
            data.get("vendor_oui"), data.get("auth"), data.get("encryption"), data.get("radio"),
            data.get("beacon_interval"), 1 if data.get("has_wps") else 0,
            data.get("scanner_platform"), data.get("app_version"),
            _now(), _now(), 1, data.get("rssi"), data.get("rssi")
        ))
        conn.commit()
        return cur.lastrowid

def add_sighting(ssid, bssid_hash, channel, rssi, vendor_oui=None, auth=None, encryption=None,
                 radio=None, beacon_interval=None, has_wps=False, scanner_platform=None, app_version=None):
    if not bssid_hash:
        return
    conn = connect()
    data = {
        "ssid": ssid,
        "bssid_hash": bssid_hash,
        "channel": int(channel) if channel is not None and str(channel).isdigit() else None,
        "rssi": int(rssi) if rssi is not None and str(rssi).lstrip("-").isdigit() else None,
        "vendor_oui": vendor_oui,
        "auth": auth,
        "encryption": encryption,
        "radio": radio,
        "beacon_interval": int(beacon_interval) if beacon_interval and str(beacon_interval).isdigit() else None,
        "has_wps": bool(has_wps),
        "scanner_platform": scanner_platform,
        "app_version": app_version,
    }
    _merge_sighting(conn, data)

def add_friendly(ssid):
    conn = connect()
    cur = conn.cursor()
    cur.execute("INSERT OR IGNORE INTO friendly (ssid) VALUES (?)", (ssid,))
    conn.commit()

def list_friendly():
    conn = connect()
    return conn.execute("SELECT * FROM friendly ORDER BY ssid ASC").fetchall()

def list_sightings(limit=500):
    conn = connect()
    return conn.execute("""
        SELECT * FROM sightings
        ORDER BY last_seen DESC
        LIMIT ?
    """, (limit,)).fetchall()

def log_upload(filename):
    conn = connect()
    conn.execute("INSERT INTO uploads(filename) VALUES (?)", (filename,))
    conn.commit()

def correlation_groups():
    conn = connect()
    rows = conn.execute("""
        SELECT ssid, bssid_hash, COUNT(*) as n, MIN(first_seen) as first_seen, MAX(last_seen) as last_seen
        FROM sightings
        GROUP BY ssid, bssid_hash
        HAVING n >= 2
        ORDER BY n DESC, last_seen DESC
    """).fetchall()
    return rows
