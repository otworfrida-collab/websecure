# WebSecure — Web Vulnerability Scanning & Monitoring Tool

> A lightweight, affordable web vulnerability scanner for small business websites.
> Final Year Cybersecurity Project.

---

## Table of Contents
1. [Features](#features)
2. [Architecture](#architecture)
3. [Folder Structure](#folder-structure)
4. [Database Schema](#database-schema)
5. [Setup & Running](#setup--running)
6. [API Reference](#api-reference)
7. [Vulnerability Checks](#vulnerability-checks)
8. [System Diagrams](#system-diagrams)

---

## Features

| Module | Capabilities |
|--------|-------------|
| Authentication | Registration, login, bcrypt hashing, sessions |
| Website Management | Add, label, delete, toggle auto-scan |
| Vulnerability Scanner | 9 check categories, severity scoring |
| Monitoring | APScheduler 24h auto-scan |
| Alerts | Dashboard notifications + email (SMTP) |
| Reports | Interactive dashboard + downloadable PDF |
| REST API | JSON endpoints for all scan data |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        User Browser                          │
└────────────────────────┬─────────────────────────────────────┘
                         │ HTTP / HTTPS
┌────────────────────────▼─────────────────────────────────────┐
│                   Flask Web Interface                         │
│  Routes: /dashboard  /websites  /scans  /api  /reports       │
└──────┬──────────┬──────────────┬───────────────┬─────────────┘
       │          │              │               │
┌──────▼───┐ ┌────▼─────┐ ┌─────▼──────┐ ┌─────▼──────────┐
│   Auth   │ │ Website  │ │  Scanner   │ │  Alert System  │
│ Module   │ │  Mgmt    │ │  Engine    │ │  (Dashboard +  │
│ (bcrypt) │ │          │ │ (9 checks) │ │   Email SMTP)  │
└──────────┘ └──────────┘ └─────┬──────┘ └────────────────┘
                                 │
                    ┌────────────▼───────────┐
                    │      SQLite / PostgreSQL │
                    │  users, websites, scans  │
                    │  vulnerabilities, alerts │
                    └────────────────────────-┘
                                 │
                    ┌────────────▼───────────┐
                    │    PDF Report Engine    │
                    │      (ReportLab)        │
                    └────────────────────────┘
```

---

## Folder Structure

```
websecure/
├── run.py                      # Entry point
├── .env                        # Environment variables (edit this)
├── requirements.txt
│
├── app/
│   ├── __init__.py             # App factory, extension init
│   │
│   ├── models/
│   │   └── models.py           # User, Website, Scan, Vulnerability, Alert
│   │
│   ├── scanner/
│   │   ├── engine.py           # Vulnerability scanning engine (9 checks)
│   │   └── runner.py           # Scan orchestrator + DB persistence
│   │
│   ├── routes/
│   │   ├── auth.py             # Register, login, logout
│   │   ├── dashboard.py        # Main dashboard
│   │   ├── websites.py         # Add/delete/manage websites
│   │   ├── scans.py            # Trigger scans, view results
│   │   ├── reports.py          # PDF report generation
│   │   └── api.py              # REST API (JSON)
│   │
│   └── utils/
│       └── scheduler.py        # APScheduler auto-scan jobs
│
└── templates/
    ├── base.html               # Sidebar layout, styles
    ├── auth/
    │   ├── login.html
    │   └── register.html
    ├── dashboard/
    │   └── home.html           # Stats, charts, alerts
    ├── websites/
    │   ├── list.html
    │   └── add.html
    └── scans/
        ├── detail.html         # Full vulnerability report
        └── history.html        # Scan history table
```

---

## Database Schema

```sql
-- Users table
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,              -- bcrypt hash
    created_at    DATETIME DEFAULT NOW,
    is_active     BOOLEAN DEFAULT TRUE
);

-- Websites table
CREATE TABLE websites (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
    url        TEXT NOT NULL,
    label      TEXT,
    date_added DATETIME DEFAULT NOW,
    auto_scan  BOOLEAN DEFAULT TRUE
);

-- Scans table
CREATE TABLE scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    website_id     INTEGER REFERENCES websites(id) ON DELETE CASCADE,
    scan_date      DATETIME DEFAULT NOW,
    status         TEXT DEFAULT 'pending',   -- pending|running|done|failed
    result_summary TEXT,
    total_vulns    INTEGER DEFAULT 0,
    risk_score     REAL DEFAULT 0.0,         -- 0-100 composite score
    duration_secs  REAL DEFAULT 0.0
);

-- Vulnerabilities table
CREATE TABLE vulnerabilities (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id            INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    vulnerability_type TEXT NOT NULL,
    risk_level         TEXT NOT NULL,         -- High | Medium | Low
    description        TEXT NOT NULL,
    recommendation     TEXT,
    evidence           TEXT,
    severity_score     REAL DEFAULT 0.0       -- 1-10
);

-- Alerts table
CREATE TABLE alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER REFERENCES users(id),
    scan_id    INTEGER REFERENCES scans(id),
    message    TEXT NOT NULL,
    is_read    BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT NOW,
    alert_type TEXT DEFAULT 'dashboard'       -- dashboard | email
);
```

---

## Setup & Running

### Prerequisites
- Python 3.9+
- pip

### 1. Install dependencies
```bash
pip install Flask Flask-SQLAlchemy Flask-Login Flask-Mail \
            Flask-APScheduler bcrypt requests beautifulsoup4 \
            cryptography python-dotenv reportlab
```

### 2. Configure environment
Edit `.env`:
```
SECRET_KEY=your-random-secret-key-here
DATABASE_URL=sqlite:///websecure.db

# Optional: email alerts
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=your-email@gmail.com

SCAN_INTERVAL_HOURS=24
```

### 3. Run
```bash
python run.py
```

Open **http://127.0.0.1:5000** in your browser.

### 4. First use
1. Click **Create one free** to register
2. Click **Add Website** and enter a URL you own
3. Click **Scan Now** to run your first vulnerability scan
4. View the report and download the PDF

---

## API Reference

All API endpoints require login. Base path: `/api`

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/websites` | List your websites |
| GET | `/api/websites/<id>/scans` | List scans for a website |
| GET | `/api/scans/<id>` | Full scan detail with vulnerabilities |
| GET | `/api/alerts` | Your alerts |
| POST | `/api/alerts/<id>/read` | Mark alert as read |

**Example response** (`GET /api/scans/1`):
```json
{
  "id": 1,
  "status": "done",
  "scan_date": "2024-01-15T14:30:00",
  "risk_score": 67.5,
  "total_vulns": 8,
  "vulnerabilities": [
    {
      "type": "Missing Header: Content-Security-Policy",
      "risk_level": "High",
      "description": "CSP header is missing...",
      "recommendation": "Add Content-Security-Policy header...",
      "severity_score": 8.0
    }
  ]
}
```

---

## Vulnerability Checks

| Check | Risk Level | Description |
|-------|-----------|-------------|
| HTTPS / SSL | High | Detects HTTP-only sites, expired/invalid certificates |
| Content-Security-Policy | High | Missing CSP header allows XSS attacks |
| Strict-Transport-Security | High | Missing HSTS allows protocol downgrade attacks |
| X-Frame-Options | Medium | Missing header allows clickjacking |
| X-Content-Type-Options | Low | Missing header allows MIME sniffing |
| Open Ports (8080/8888/3000) | Medium | Unexposed dev/alt ports |
| .git / .env exposure | High | Source code or credentials in web root |
| /admin, /phpmyadmin exposure | High | Admin interfaces exposed publicly |
| SQL Injection indicators | High | Error-based SQLi detection |
| Reflected XSS | High | User input reflected unescaped |
| Login form over HTTP | High | Credentials sent unencrypted |
| Insecure Cookies | Medium | Missing Secure/HttpOnly/SameSite flags |
| Mixed Content | Medium | HTTP resources on HTTPS page |
| Server Header Leakage | Low | Server version fingerprinting |

---

## System Diagrams

### Use Case Diagram
```
         ┌─────────────────────────────────────────────┐
         │                WebSecure System               │
         │                                               │
         │  ┌─────────────────┐  ┌──────────────────┐   │
         │  │   <<use case>>  │  │   <<use case>>   │   │
         │  │ Register/Login  │  │  Add Website     │   │
         │  └────────┬────────┘  └────────┬─────────┘   │
         │           │                    │              │
[User]──►│  ┌────────▼────────┐  ┌────────▼─────────┐   │
         │  │   <<use case>>  │  │   <<use case>>   │   │
         │  │  View Dashboard │  │  Trigger Scan    │   │
         │  └─────────────────┘  └────────┬─────────┘   │
         │                                │              │
         │  ┌─────────────────┐  ┌────────▼─────────┐   │
         │  │   <<use case>>  │  │   <<use case>>   │   │
         │  │ Receive Alerts  │  │  View/Export     │   │
         │  │                 │  │  Report (PDF)    │   │
         │  └─────────────────┘  └──────────────────┘   │
         │                                               │
         │  ┌─────────────────────────────────────────┐  │
         │  │   <<use case>>                          │  │
[Scheduler]►│  Auto-Scan (every 24h)                  │  │
         │  └─────────────────────────────────────────┘  │
         └─────────────────────────────────────────────┘
```

### Sequence Diagram — Manual Scan
```
User        Browser      Flask API    Scanner     Database    Email
 │            │              │           │            │          │
 │─ POST ─────►              │           │            │          │
 │  /scan     │──── POST ───►│           │            │          │
 │            │              │─ Scan() ─►│            │          │
 │            │              │           │─ check_https()        │
 │            │              │           │─ check_headers()      │
 │            │              │           │─ check_ports()        │
 │            │              │           │─ check_dirs()         │
 │            │              │           │─ check_sqli()         │
 │            │              │           │─ check_xss()          │
 │            │              │           │─ return findings ─────►
 │            │              │◄────────────────────── findings   │
 │            │              │─ INSERT scan ──────────►          │
 │            │              │─ INSERT vulns ─────────►          │
 │            │              │─ INSERT alert ─────────►          │
 │            │              │─────────────────────────────────►Send
 │            │◄── redirect  │                                   │
 │◄───────────│   /scan/id   │
```

### Component Diagram
```
┌─────────────────────────────────────────────────────────────┐
│                       WebSecure App                          │
│                                                              │
│  ┌──────────────┐   ┌──────────────┐   ┌─────────────────┐  │
│  │  Auth Module │   │ Website Mgmt │   │  Dashboard UI   │  │
│  │  (bcrypt)    │   │  (CRUD)      │   │  (Chart.js)     │  │
│  └──────┬───────┘   └──────┬───────┘   └────────┬────────┘  │
│         │                  │                    │            │
│  ┌──────▼──────────────────▼────────────────────▼─────────┐  │
│  │                    Flask Router                         │  │
│  └──────┬──────────────────────────────────────────────────┘  │
│         │                                                    │
│  ┌──────▼───────────────────────────────────────────────┐   │
│  │              Vulnerability Scanner Engine             │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──────────┐  │   │
│  │  │ HTTPS   │ │ Headers │ │  Ports  │ │  Dirs    │  │   │
│  │  │ Checker │ │ Checker │ │ Scanner │ │  Scanner │  │   │
│  │  └─────────┘ └─────────┘ └─────────┘ └──────────┘  │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──────────┐  │   │
│  │  │  SQLi   │ │   XSS   │ │  Login  │ │ Cookies  │  │   │
│  │  │ Checker │ │ Checker │ │  Forms  │ │ Checker  │  │   │
│  │  └─────────┘ └─────────┘ └─────────┘ └──────────┘  │   │
│  └──────┬────────────────────────────────────────────┘   │
│         │                                                   │
│  ┌──────▼────────┐   ┌────────────────┐   ┌────────────┐   │
│  │   Database    │   │  Alert System  │   │ PDF Report │   │
│  │ (SQLAlchemy)  │   │ (Mail + Panel) │   │(ReportLab) │   │
│  └───────────────┘   └────────────────┘   └────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         APScheduler (24h auto-scan job)              │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Flowchart — Scan Process
```
START
  │
  ▼
User triggers scan (manual or scheduled)
  │
  ▼
Create Scan record (status=running)
  │
  ▼
Run VulnerabilityScanner(url)
  │
  ├─► Check 1: HTTPS / SSL ──────────┐
  ├─► Check 2: Security Headers ──────┤
  ├─► Check 3: Open Ports ────────────┤──► findings[]
  ├─► Check 4: Directory Exposure ────┤
  ├─► Check 5: SQL Injection ─────────┤
  ├─► Check 6: XSS ──────────────────┤
  ├─► Check 7: Login Forms ───────────┤
  ├─► Check 8: Cookies ───────────────┤
  └─► Check 9: Mixed Content ─────────┘
  │
  ▼
Compute Risk Score (0-100)
  │
  ▼
Save Vulnerabilities to DB
  │
  ▼
Are there HIGH findings?
  │
  ├── YES ──► Create Dashboard Alert
  │            │
  │            └──► Send Email (if configured)
  │
  └── NO ──► No alert
  │
  ▼
Update Scan (status=done, score, summary)
  │
  ▼
Redirect to Scan Report
  │
  ▼
END
```

---

## Risk Scoring

Each vulnerability has a severity score (1–10). The composite risk score is calculated as:

```
weighted_sum = Σ (severity_score × weight)
  where weight: High=3.0, Medium=2.0, Low=1.0

normalised = min(100, weighted_sum / (n_vulns × 30) × 100)
risk_score = normalised × 0.7 + volume_factor × 100 × 0.3
```

| Score Range | Label |
|-------------|-------|
| 0–29 | Low Risk |
| 30–59 | Medium Risk |
| 60–100 | High Risk |

---

## Security Notes

- Passwords are hashed with **bcrypt** (cost factor 12)
- Session cookies have `HttpOnly` and `SameSite=Lax` flags
- All scans require authentication; users only see their own data
- Scanner uses a custom User-Agent identifying itself as a security tool
- **Only scan websites you own or have explicit permission to test**

---

*WebSecure — Final Year Cybersecurity Project*
#   w e b s e c u r e  
 