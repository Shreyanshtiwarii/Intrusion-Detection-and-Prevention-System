# CyberShield IDS/IPS

**AI Assisted Real-Time Intrusion Detection & Prevention System**

A full-stack security operations console that captures live network traffic, detects
attacks using a rule-based detection + classification engine, automatically blocks
malicious IP addresses, monitors critical files for tampering, and generates
PDF security reports -- all through a real-time, dark-themed SOC dashboard.

> Built as a final-year college project. All detection logic is rule-based and runs
> entirely locally -- no external AI APIs are used.

---

## Features

- **Authentication** -- session-based login, password hashing, protected routes
- **Live Dashboard** -- packet counter, threat counter, CPU/RAM/disk, blocked IPs, charts, live feed (SocketIO)
- **Packet Capture** -- TCP / UDP / ICMP / ARP / DNS via Scapy, live table view
- **IDS Engine** -- SYN/UDP/ICMP flood, port scan, SQL injection, XSS, directory traversal,
  command injection, brute force, suspicious user agents, excessive requests, ARP spoofing
- **AI Threat Classification** -- rule-based severity, 0-100 threat score, confidence,
  human-readable description, and suggested mitigation for every detection
- **IPS Engine** -- automatic + manual IP blocking, temporary/permanent blocks, whitelist,
  unblock, full audit log, best-effort OS firewall enforcement (iptables / netsh)
- **File Integrity Monitoring** -- SHA-256 hashing of critical files with change alerts
- **Logs** -- unified viewer across system/alert/packet/blocked-IP logs with search,
  filters, pagination, CSV export, and PDF export
- **Reports** -- daily/weekly/monthly PDF reports with charts and summaries
- **Settings** -- monitoring toggle, auto-block toggle, live-editable thresholds,
  notification sound, logging level

---

## Technology Stack

**Backend:** Python 3.12, Flask, Flask-SocketIO, SQLAlchemy, SQLite, Scapy, psutil,
hashlib, pandas, threading, schedule, reportlab, python-dotenv

**Frontend:** HTML5, CSS3, Vanilla JavaScript, Chart.js, Font Awesome (no frameworks)

---

## Installation

### 1. Create a virtual environment

```bash
python3 -m venv venv

# Linux / macOS
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

> **Note (Windows):** Scapy requires [Npcap](https://npcap.com/) to be installed
> separately for packet capture to work.

### 3. Configure environment variables

A `.env` file with sensible defaults is already included. Review and adjust as needed
(interface name, thresholds, admin credentials, etc.) before running in production.

### 4. Run the application

Packet capture requires elevated privileges to open a raw socket.

```bash
# Linux / macOS
sudo venv/bin/python app.py

# Windows (run terminal as Administrator)
python app.py
```

The server starts at **http://localhost:5000**.

### 5. Log in

```
Username: admin
Password: admin123
```

The database, tables, and default admin account are created automatically on first run
(SQLite file at `database/cybershield.db`).

> If you don't run with elevated privileges, the rest of the application (dashboard,
> alerts, IPS, FIM, reports, settings) still works normally -- only live packet capture
> will be unavailable, and the dashboard will show the sniffer as stopped.

---

## Database

SQLite database managed through SQLAlchemy ORM. Tables:

| Table | Purpose |
|---|---|
| `users` | Authentication accounts |
| `alerts` | IDS-detected threats with AI classification |
| `blocked_ips` | IPS blocklist (active + historical) |
| `packet_logs` | Captured packet metadata |
| `system_logs` | Application/event logs |
| `reports` | Generated PDF report metadata |
| `settings` | Runtime-configurable thresholds and toggles |
| `login_history` | Login attempt audit trail |
| `file_hashes` | File Integrity Monitoring baseline hashes |

---

## Packet Capture

`packet_capture/sniffer.py` runs Scapy's `sniff()` in a dedicated daemon thread so it
never blocks the Flask/SocketIO event loop. Each packet is parsed by
`packet_capture/parser.py` into a normalized record (protocol, IPs, ports, size, flags),
queued, batch-written to the database, forwarded to the IDS engine, and broadcast live
to the dashboard over SocketIO.

## IDS Engine

`ids_engine/detector.py` orchestrates two detection layers:

1. **Rate/behavior-based rules** (`ids_engine/rules.py`) -- sliding-window counters
   per source IP detect floods, port scans, and brute-force login attempts. Thresholds
   are read live from the Settings table, so changes in the UI apply immediately.
2. **Signature-based rules** (`ids_engine/signatures.py`) -- regex signatures scan
   packet payloads and HTTP requests for SQL injection, XSS, directory traversal,
   command injection, and known malicious User-Agent strings.

Every detection is scored by `ids_engine/classifier.py`, a rule-based classifier that
assigns severity, a 0-100 threat score (with escalation for repeat offenders and
volume overshoot), a confidence percentage, a plain-English description, and a
suggested mitigation -- entirely offline, no external AI APIs.

## IPS Engine

`ips_engine/blocker.py` maintains the blocklist and decides when to auto-block based on
attack severity/type. Blocks are enforced at the application layer (checked on every
Flask request via `before_request`) and, best-effort, at the OS firewall layer through
`ips_engine/firewall.py` (`iptables` on Linux, `netsh` on Windows). Temporary blocks
expire automatically via a background scheduler sweep.

---

## Screenshots

_Add screenshots of the Dashboard, Packet Capture, Alerts, IP Blocklist, and Reports
pages here after running the application locally._

---

## Future Improvements

- Machine-learning-based anomaly detection to complement the rule-based engine
- Multi-user roles (analyst / admin) with granular permissions
- Distributed sensor deployment with a central aggregation server
- GeoIP-based attacker mapping on the dashboard
- Email/SMS/webhook alert integrations
- Deep packet inspection for encrypted traffic metadata (JA3/JA3S fingerprinting)

---

## Project Structure

```
CyberShield_IDS_IPS/
├── app.py                 # Application entry point
├── config.py               # Environment-based configuration
├── database.py              # SQLAlchemy bootstrap + seeding
├── requirements.txt
├── .env
├── authentication/          # Login/session logic + route decorators
├── models/                  # SQLAlchemy ORM models
├── routes/                  # Flask blueprints (one per feature)
├── ids_engine/               # Detection rules, signatures, AI classifier
├── ips_engine/                # Blocklist manager + OS firewall control
├── packet_capture/            # Scapy sniffer + packet parser
├── monitoring/                # System resource monitor + file integrity monitor
├── reports/                   # Report aggregation + PDF export
├── utils/                     # Logger, validators, helpers
├── database/                  # SQLite database file (created at runtime)
├── logs/                      # Rotating log file + generated PDF reports
├── static/
│   ├── css/                   # Per-page stylesheets
│   ├── js/                    # Per-page vanilla JS
│   ├── images/, icons/, sounds/
└── templates/                 # Jinja2 HTML templates
```
