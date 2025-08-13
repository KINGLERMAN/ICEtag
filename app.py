import os, json, hashlib, csv, threading, webbrowser
from flask import Flask, request, render_template, jsonify, Response
from dotenv import load_dotenv
import db
import scanner

# --- Load env + config ---
load_dotenv()
PORT = int(os.getenv("PORT", "5005"))
PEPPER = os.getenv("PEPPER", "change-this")
STORE_RAW = os.getenv("STORE_RAW_BSSID", "false").lower() == "true"
APP_VERSION = os.getenv("APP_VERSION", "0.2.0")

app = Flask(__name__)

# Initialize DB at import time
db.init_db()

@app.teardown_appcontext
def close_db(err):
    db.close_conn()

def bssid_hash(bssid: str) -> str | None:
    if not bssid:
        return None
    raw = (bssid.strip().lower() + "|" + PEPPER).encode("utf-8")
    import hashlib as _h
    return _h.sha256(raw).hexdigest()

# ----------------- Pages -----------------
@app.get("/")
def home():
    return render_template("index.html", app_version=APP_VERSION)

@app.get("/sightings")
def sightings_page():
    rows = db.list_sightings(limit=500)
    return render_template("sightings.html", rows=rows, app_version=APP_VERSION)

@app.get("/friendly")
def friendly_page():
    return render_template("friendly.html", rows=db.list_friendly(), app_version=APP_VERSION)

@app.post("/friendly")
def friendly_add():
    ssid = (request.form.get("ssid") or "").strip()
    if ssid:
        db.add_friendly(ssid)
    return jsonify({"ok": True})

@app.get("/correlate")
def correlate_page():
    groups = db.correlation_groups()
    return render_template("correlate.html", groups=groups, app_version=APP_VERSION)

@app.route("/uploads", methods=["GET", "POST"])
def uploads_page():
    if request.method == "POST":
        file = request.files.get("file")
        if not file:
            return "No file", 400
        name = file.filename
        buf = file.read()
        try:
            count = 0
            # JSON import (our native export)
            if name.lower().endswith(".json"):
                data = json.loads(buf.decode("utf-8"))
                for r in data:
                    db.add_sighting(
                        ssid=r.get("ssid"),
                        bssid_hash=r.get("bssid_hash"),
                        channel=r.get("channel"),
                        rssi=r.get("rssi"),
                        vendor_oui=r.get("vendor_oui"),
                        auth=r.get("auth"),
                        encryption=r.get("encryption"),
                        radio=r.get("radio"),
                        beacon_interval=r.get("beacon_interval"),
                        has_wps=r.get("has_wps"),
                        scanner_platform=r.get("scanner_platform"),
                        app_version=r.get("app_version"),
                    )
                    count += 1
            # CSV import
            elif name.lower().endswith(".csv"):
                import io, csv
                f = io.StringIO(buf.decode("utf-8"))
                rdr = csv.DictReader(f)
                for r in rdr:
                    db.add_sighting(
                        ssid=r.get("ssid"),
                        bssid_hash=r.get("bssid_hash"),
                        channel=int(r.get("channel") or 0),
                        rssi=int(r.get("rssi") or 0),
                        vendor_oui=r.get("vendor_oui"),
                        auth=r.get("auth"),
                        encryption=r.get("encryption"),
                        radio=r.get("radio"),
                        beacon_interval=int(r.get("beacon_interval") or 0),
                        has_wps=(str(r.get("has_wps")).lower() in ("1","true","yes")),
                        scanner_platform=r.get("scanner_platform"),
                        app_version=r.get("app_version"),
                    )
                    count += 1
            else:
                return "Unsupported file type", 400
            db.log_upload(name)
            return jsonify({"ok": True, "imported": count})
        except Exception as e:
            return jsonify({"ok": False, "error": str(e)}), 400
    return render_template("uploads.html", app_version=APP_VERSION)

# ----------------- APIs -----------------
@app.post("/scan")
def scan_route():
    results, diag = scanner.scan()  # results:list[dict], diag:dict
    out = []
    import platform
    scanner_platform = platform.system()
    for r in results:
        h = bssid_hash(r.get("bssid"))
        vendor_oui = r.get("vendor_oui") or r.get("bssid_oui")
        db.add_sighting(
            ssid=r.get("ssid"),
            bssid_hash=h,
            channel=r.get("channel"),
            rssi=r.get("rssi"),
            vendor_oui=vendor_oui,
            auth=r.get("auth"),
            encryption=r.get("encryption"),
            radio=r.get("radio"),
            beacon_interval=r.get("beacon_interval"),
            has_wps=bool(r.get("has_wps")),
            scanner_platform=scanner_platform,
            app_version=APP_VERSION,
        )
        item = {
            "ssid": r.get("ssid"),
            "bssid": r.get("bssid") if STORE_RAW else None,
            "bssid_hash": h,
            "vendor_oui": vendor_oui,
            "channel": r.get("channel"),
            "band": r.get("band"),
            "rssi": r.get("rssi"),
            "rssi_pct": r.get("rssi_pct"),
            "auth": r.get("auth"),
            "encryption": r.get("encryption"),
            "radio": r.get("radio"),
            "beacon_interval": r.get("beacon_interval"),
            "has_wps": r.get("has_wps"),
            "scanner_platform": scanner_platform,
        }
        out.append(item)
    payload = {
        "count": len(out),
        "items": out,
        "diag": diag,
        "app_version": APP_VERSION
    }
    return jsonify(payload)

@app.get("/export.csv")
def export_csv():
    rows = db.list_sightings(limit=5000)
    fieldnames = ["ssid","bssid_hash","channel","rssi","vendor_oui","auth","encryption",
                  "radio","beacon_interval","has_wps","scanner_platform","app_version",
                  "first_seen","last_seen","seen_count","rssi_min","rssi_max"]
    def gen():
        yield ",".join(fieldnames) + "\n"
        for r in rows:
            row = [str(r.get(k,"")) if r.get(k) is not None else "" for k in fieldnames]
            yield ",".join(x.replace(",", ";") for x in row) + "\n"
    return Response(gen(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=sightings_export.csv"})

# ----------------- Browser auto-open -----------------
def _open_browser_later():
    url = f"http://127.0.0.1:{PORT}/"
    try:
        webbrowser.open(url, new=1, autoraise=True)
    except Exception:
        pass

if __name__ == "__main__":
    threading.Timer(0.8, _open_browser_later).start()
    app.run(host="127.0.0.1", port=PORT, debug=True)
