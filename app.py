
import os
import threading
import webbrowser
from datetime import datetime, timezone
from flask import Flask, jsonify, render_template, request
import db as dbm
import scanner

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# Ensure DB is initialized at startup
dbm.init_db()

def _ts_utc():
    return int(datetime.now(timezone.utc).timestamp())

@app.route("/")
def home():
    latest = dbm.get_latest_scan()
    return render_template("index.html", latest=latest)

@app.route("/api/scan", methods=["POST"])
def api_scan():
    # Wi‑Fi + LAN scan
    wifi = scanner.scan_wifi()
    lan = scanner.scan_lan()
    diag = scanner.scan_diagnostics(wifi=wifi, lan=lan)

    rec = {
        "ts_utc": _ts_utc(),
        "wifi": wifi,
        "lan": lan,
        "diagnostics": diag,
    }
    dbm.save_scan(rec)
    return jsonify(rec)

@app.route("/api/latest", methods=["GET"])
def api_latest():
    data = dbm.get_latest_scan()
    return jsonify(data or {"error":"no scans yet"})

def _open_browser_once(port: int):
    def _open():
        url = f"http://127.0.0.1:{port}"
        try:
            webbrowser.open_new(url)
        except Exception:
            pass
    threading.Timer(1.2, _open).start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5005"))
    # Auto-open default browser
    _open_browser_once(port)
    app.run(host="127.0.0.1", port=port, debug=False)
