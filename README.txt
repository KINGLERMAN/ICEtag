# ICEtag Patch v0.2.8

Adds:
- **Persistent Mode** (start/stop, interval) — keeps scanning and saving in the background.
- **LAN Devices page** (`/lan`) — simple table of devices from the DB.
- Home page shows counts and link to LAN page. Styling kept dark/minimal, a touch cleaner.

Install:
```powershell
cd C:\Users\KINGLERMAN\Scripts\ICEtag
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

The browser opens automatically. Use the “Persistent Mode” button to toggle background scanning.
