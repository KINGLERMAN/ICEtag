
import os, sqlite3, json
from datetime import datetime, timezone

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "ice.db")

DDL = """
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_utc INTEGER NOT NULL,
  payload TEXT NOT NULL
);
"""

def _conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def init_db():
    with _conn() as con:
        con.execute(DDL)
        con.commit()

def save_scan(scan_dict):
    init_db()
    with _conn() as con:
        con.execute("INSERT INTO scans(ts_utc, payload) VALUES(?,?)",
                    (int(scan_dict.get("ts_utc", 0)), json.dumps(scan_dict)))
        con.commit()

def get_latest_scan():
    init_db()
    with _conn() as con:
        cur = con.execute("SELECT payload FROM scans ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        if not row:
            return None
        return json.loads(row[0])
