# SecureScan – Advanced Multi-Threaded Network Port Scanner

SecureScan is a modern, production-quality cybersecurity **Network Port Scanner** built using **Python 3**, **Flask**, **Socket Programming**, **`ThreadPoolExecutor` Concurrency**, **SQLite**, and **ReportLab PDF Generation**.

Featuring a sleek neon dark cybersecurity dashboard UI, real-time live port scanning progress, threat level risk scoring, automated security remediation guidelines, and instant report exports in PDF, CSV, and JSON formats.

---

## Features Overview

1. **Multi-Threaded Socket Engine**: Fast parallel TCP port scanning using Python's built-in `socket` module and `concurrent.futures.ThreadPoolExecutor` supporting 10 to 200 concurrent threads.
2. **Real-Time Live Results**: Live progress bar, active thread counter, speed (ports/sec), estimated time remaining (ETA), and live table updates.
3. **Service & Banner Detection**: Automatic identification of 40+ common services (FTP, SSH, Telnet, SMTP, DNS, HTTP, SMB, RDP, MySQL, Postgres, Redis, MongoDB, SonarQube, etc.) with socket banner grabbing.
4. **Security Risk Meter & Remediation**: Automated risk score calculation (0–100) and actionable security recommendations for risky exposed ports (e.g. SMB 445, Telnet 23, RDP 3389, unauthenticated databases).
5. **Interactive Cybersecurity Dashboard**: Real-time stats widgets, Chart.js visual graphs (Open vs Closed distribution, top detected services), quick launcher, and security status indicator.
6. **SQLite Scan History Repository**: Persistent audit database storing target IP/host, scan duration, port metrics, risk score, and detailed port findings.
7. **Multi-Format Audit Export**: One-click generation of styled PDF audit reports (via ReportLab), CSV exports, and structured JSON files.
8. **Settings & Custom Presets**: Configurable default thread pool size, socket connection timeout, port range presets (Top 20, Top 100, Standard 1-1000), and auto-save options.
9. **Heuristics & Target Resolution**: Domain DNS resolution, reverse DNS PTR lookup, and OS fingerprinting heuristics.

---

## Tech Stack

* **Backend**: Python 3, Flask, Socket Programming, `ThreadPoolExecutor`, SQLite3, ReportLab.
* **Frontend**: HTML5, CSS3 (Neon Cyberpunk Dark Theme), Bootstrap 5, JavaScript, Chart.js, Font Awesome 6.

---

## Quick Start & Installation

### 1. Requirements
Ensure Python 3.8+ is installed on your system.

### 2. Install Dependencies
Navigate to the `SecureScan` directory and install required Python packages:

```bash
cd SecureScan
pip install -r requirements.txt
```

### 3. Run Application
Start the Flask web server:

```bash
python app.py
```

Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

---

## Folder Structure

```
SecureScan/
├── app.py                  # Flask Web Server & REST API Endpoints
├── scanner.py              # Multi-Threaded Socket Scanner Core Engine
├── services.py             # Service Detection & Vulnerability Recommendation Mapping
├── database.py             # SQLite Persistence Layer & Dashboard Queries
├── report.py               # PDF (ReportLab), CSV, & JSON Exporters
├── utils.py                # Hostname Resolution, Reverse DNS & OS Heuristics
├── requirements.txt        # Dependencies
├── README.md               # Project Documentation
├── database/
│   └── scans.db            # SQLite Database Storage
├── reports/                # Generated Audit Export Files
├── templates/
│   ├── base.html           # Main Layout & Sidebar
│   ├── dashboard.html      # Cyber Dashboard & Analytics
│   ├── scanner.html        # Scanner Control Center & Live Results Table
│   ├── history.html        # Scan Audit History Repository
│   ├── report.html         # Audit Report Viewer & Download Portal
│   └── settings.html       # Scanner Configuration Settings
└── static/
    ├── css/
    │   └── style.css       # Cyberpunk Dark Theme Stylesheet
    └── js/
        ├── particles.js    # Cyber Network Node Background Animation
        ├── main.js         # Navigation & Utilities
        ├── dashboard.js    # Chart.js Integration & Stats
        └── scanner.js      # Real-Time Live Scan State & Table Filter
```

---

## Ethical Use Disclaimer

> **IMPORTANT**: SecureScan is created strictly for educational purposes, defensive security auditing, and system administration. Scanning unauthorized external targets without explicit consent from the infrastructure owner is illegal and violates computer crime laws. Always test responsibly on owned systems or loopback interfaces (`127.0.0.1`).
