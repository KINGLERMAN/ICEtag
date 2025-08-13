import sqlite3, os, sys, time

db = sys.argv[1] if len(sys.argv) > 1 else "ice.db"
print("DB:", os.path.abspath(db))
if not os.path.exists(db):
    print("DB file not found. Start the app once or run a scan.")
    sys.exit(0)

con = sqlite3.connect(db)
cur = con.cursor()

cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY 1;")
tables = [r[0] for r in cur.fetchall()]
print("Tables:", tables)

if "sightings" in tables:
    cur.execute("SELECT COUNT(*) FROM sightings;")
    total = cur.fetchone()[0]
    print("Sightings count:", total)
    cur.execute("SELECT ssid,bssid,channel,rssi,datetime(ts,'unixepoch') FROM sightings ORDER BY ts DESC LIMIT 5;")
    for row in cur.fetchall():
        print(" •", row)
else:
    print("Table 'sightings' not found — schema may create on first scan.")

con.close()
