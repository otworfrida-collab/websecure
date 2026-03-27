# WebSecure — Web Vulnerability Scanning & Monitoring Tool

> A lightweight, affordable web vulnerability scanner for small business websites.
> **Now with MongoDB Atlas integration** for cloud-based data persistence.
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
| Authentication | Registration, login, bcrypt hashing, sessions, Flask-Login |
| Website Management | Add, label, delete, toggle auto-scan monitoring |
| Vulnerability Scanner | 9 check categories, severity scoring, real-time reporting |
| Monitoring | APScheduler 24h auto-scan, scheduled jobs |
| Alerts | Dashboard notifications + email (SMTP) |
| Reports | Interactive dashboard + downloadable PDF |
| REST API | JSON endpoints for all scan data |
| Database | MongoDB Atlas cloud database with PyMongo driver |

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
                    │  MongoDB Atlas Cloud   │
                    │  users, websites,      │
                    │  scans, vulns, alerts  │
                    └────────────────────────┘
                                 │
                    ┌────────────▼───────────┐
                    │    PDF Report Engine    │
                    │      (ReportLab)        │
                    └────────────────────────┘
```

---

## Folder Structure

```
websecure_clean/
├── run.py                      # Entry point
├── .env                        # Environment variables (EDIT THIS)
├── requirements.txt            # Python dependencies
├── README.md                   # This file
│
├── app/
│   ├── __init__.py             # App factory, MongoDB init
│   │
│   ├── models/
│   │   └── models.py           # MongoDB collections: User, Website, Scan, Vulnerability, Alert
│   │
│   ├── scanner/
│   │   ├── engine.py           # Vulnerability scanning engine (9 checks)
│   │   └── runner.py           # Scan orchestrator + MongoDB persistence
│   │
│   ├── routes/
│   │   ├── auth.py             # Register, login, logout
│   │   ├── dashboard.py        # Main dashboard + statistics
│   │   ├── websites.py         # Add/delete/manage websites
│   │   ├── scans.py            # Trigger scans, view results
│   │   ├── reports.py          # PDF report generation
│   │   └── api.py              # REST API (JSON endpoints)
│   │
│   └── utils/
│       └── scheduler.py        # APScheduler auto-scan jobs
│
├── templates/
│   ├── base.html               # Sidebar layout, navbar, styles
│   ├── auth/
│   │   ├── login.html
│   │   └── register.html
│   ├── dashboard/
│   │   └── home.html           # Stats, charts, alerts
│   ├── websites/
│   │   ├── list.html           # All monitored websites
│   │   └── add.html            # Add new website
│   └── scans/
│       ├── detail.html         # Full vulnerability report
│       └── history.html        # Scan history table
│
└── static/
    ├── css/
    │   └── custom.css          # Custom dashboard styles
    └── js/
        └── app.js              # Client-side interactivity
```

---

## Database Schema (MongoDB)

### Collections

**users** - User accounts and credentials
```javascript
{
  _id: "ObjectId",                  // MongoDB internal ID
  id: 1,                            // custom integer ID
  username: "john_doe",
  email: "john@example.com",
  password_hash: "$2b$12$...",      // bcrypt hash
  created_at: ISODate("2024-01-15"),
  is_active: true
}
```

**websites** - Websites to monitor
```javascript
{
  _id: "ObjectId",
  id: 1,
  user_id: 1,                       // reference to user
  url: "https://example.com",
  label: "Main Site",
  date_added: ISODate("2024-01-15"),
  auto_scan: true                   // auto-scan enabled?
}
```

**scans** - Completed scans
```javascript
{
  _id: "ObjectId",
  id: 1,
  website_id: 1,
  scan_date: ISODate("2024-01-15T14:30:00"),
  status: "done",                   // pending|running|done|failed
  result_summary: "8 vulnerabilities found",
  total_vulns: 8,
  risk_score: 67.5,                 // 0-100 composite score
  duration_secs: 15.3
}
```

**vulnerabilities** - Individual findings per scan
```javascript
{
  _id: "ObjectId",
  id: 1,
  scan_id: 1,
  vulnerability_type: "Missing Header: Content-Security-Policy",
  risk_level: "High",               // High | Medium | Low
  description: "CSP header is missing...",
  recommendation: "Add Content-Security-Policy header...",
  evidence: "Response headers: {...}",
  severity_score: 8.0               // 1-10 scale
}
```

**alerts** - User alerts (dashboard + email)
```javascript
{
  _id: "ObjectId",
  id: 1,
  user_id: 1,
  scan_id: 1,
  message: "High severity vulnerability found on example.com",
  is_read: false,
  created_at: ISODate("2024-01-15T14:35:00"),
  alert_type: "dashboard"           // dashboard | email
}
```

**counters** - Auto-increment ID sequences (internal)
```javascript
{
  _id: "users",
  sequence: 42
}
```

---

## Setup & Running

### Prerequisites
- **Python 3.9+** (tested with Python 3.13)
- **pip** package manager
- **MongoDB Atlas account** (free tier at [mongodb.com/cloud/atlas](https://mongodb.com/cloud/atlas))
- **Virtual environment** (optional but recommended)

### 1. Clone the repository
```bash
git clone https://github.com/otworfrida-collab/websecure.git
cd websecure/websecure_clean
```

### 2. Create and activate virtual environment

**Linux / macOS:**
```bash
python -m venv ../.venv
source ../.venv/bin/activate
```

**Windows:**
```bash
python -m venv ..\.venv
..\.venv\Scripts\activate.bat
```

The virtual environment location is `<workspace>/.venv` (parent directory).

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

This installs:
- **Flask 3.1.2** - Web framework
- **PyMongo[srv] 4.8+** - MongoDB driver with SRV DNS support
- **Flask-Login** - Session management
- **Flask-Mail** - Email alerts
- **Flask-APScheduler** - Background job scheduling
- **bcrypt** - Password hashing
- **requests, beautifulsoup4** - Web scraping for scanner
- **reportlab** - PDF report generation
- **python-dotenv** - Environment variable management

### 4. Configure MongoDB Atlas

1. **Create a free MongoDB Atlas cluster:**
   - Go to [mongodb.com/cloud/atlas](https://mongodb.com/cloud/atlas)
   - Sign up for a free account
   - Create a new project and cluster (free tier)

2. **Get the connection string:**
   - In Atlas, go to: **Clusters → Connect → Drivers**
   - Select **Python** and copy the connection string
   - It looks like: `mongodb+srv://<username>:<password>@<cluster>...`

3. **Create `.env` file** in project root:
```bash
# Flask Configuration
SECRET_KEY=your-random-secret-key-here-change-this
FLASK_ENV=development

# MongoDB Atlas Connection
MONGODB_URI=mongodb+srv://<username>:<password>@<cluster-name>.mongodb.net/?retryWrites=true&w=majority
MONGODB_DB=websecure

# Optional: Email Alerts (Gmail example)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-specific-password
MAIL_DEFAULT_SENDER=your-email@gmail.com

# Scan Settings
SCAN_INTERVAL_HOURS=24
```

**Note:** For Gmail, use an [App Password](https://myaccount.google.com/apppasswords) instead of your regular password.

### 5. Run the application
```bash
python run.py
```

The application will:
1. Connect to MongoDB Atlas using your `MONGODB_URI`
2. Create required database indexes automatically
3. Start the Flask development server

Open **http://127.0.0.1:5000** in your browser.

### 6. First use
1. Click **"Create Account"** to register
2. Click **"Add Website"** and enter a URL you own
3. Click **"Scan Now"** to run your first vulnerability scan
4. View the detailed report and download PDF if needed

---

## API Reference

All API endpoints require authentication (login). Base path: `/api`

| Method | Endpoint | Description | Returns |
|--------|----------|-------------|---------|
| GET | `/api/websites` | List all your websites | Array of website objects |
| GET | `/api/websites/<id>/scans` | List all scans for a website | Array of scan objects |
| GET | `/api/scans/<id>` | Full scan detail with findings | Scan object + vulnerabilities |
| GET | `/api/alerts` | Get your recent alerts | Array of alert objects |
| POST | `/api/alerts/<id>/read` | Mark alert as read | Updated alert object |

**Example Response** (`GET /api/scans/1`):
```json
{
  "id": 1,
  "website_id": 1,
  "status": "done",
  "scan_date": "2024-01-15T14:30:00Z",
  "risk_score": 67.5,
  "total_vulns": 8,
  "duration_secs": 15.3,
  "vulnerabilities": [
    {
      "id": 1,
      "type": "Missing Header: Content-Security-Policy",
      "risk_level": "High",
      "description": "Content-Security-Policy header is not set...",
      "recommendation": "Add CSP header to all responses...",
      "severity_score": 8.0
    },
    {
      "id": 2,
      "type": "Missing HSTS Header",
      "risk_level": "High",
      "description": "Strict-Transport-Security is missing...",
      "severity_score": 7.5
    }
  ]
}
```

---

## Vulnerability Checks

The scanner performs 9 categories of security checks:

| Check | Risk Level | Description |
|-------|-----------|-------------|
| **HTTPS/SSL** | High | Detects HTTP-only sites, expired/invalid certificates, TLS version issues |
| **Content-Security-Policy** | High | Missing CSP header allows XSS attacks and injection |
| **Strict-Transport-Security** | High | Missing HSTS allows protocol downgrade attacks |
| **X-Frame-Options** | Medium | Missing header allows clickjacking and UI redressing |
| **X-Content-Type-Options** | Low | Missing header allows MIME sniffing attacks |
| **Open Ports** | Medium | Detects exposed dev/alt ports (8080, 8888, 3000) |
| **.git / .env Exposure** | High | Checks for source code or credentials in web root |
| **Admin Interface Exposure** | High | Detects exposed /admin, /phpmyadmin, etc. |
| **SQL Injection Indicators** | High | Tests for error-based SQLi detections |
| **XSS Reflected** | High | Tests for unescaped user input reflection |
| **Login Form over HTTP** | High | Detects credentials sent unencrypted |
| **Insecure Cookies** | Medium | Missing Secure/HttpOnly/SameSite flags |
| **Mixed Content** | Medium | HTTPS page loading HTTP resources |
| **Server Header Leakage** | Low | Server version fingerprinting |

---

## Troubleshooting

### MongoDB Connection Issues
```
Error: MongoDB is not initialized. Check MONGODB_URI and app startup.
```
**Solution:** Verify your `MONGODB_URI` in `.env` file. Test with:
```bash
python -c "from pymongo import MongoClient; MongoClient('your-uri', serverSelectionTimeoutMS=10000).server_info()"
```

### Port Already in Use
```bash
# Kill process on port 5000
lsof -ti:5000 | xargs kill -9
python run.py
```

### Virtual Environment
```bash
# Check if activated
which python  # Should show path to .venv/bin/python

# If not activated
source ../.venv/bin/activate  # Linux/Mac
# OR
..\.venv\Scripts\activate.bat  # Windows
```

---

## Deployment

The app includes `render.yaml` for simple deployment to Render.com:
```yaml
services:
  - type: web
    name: websecure
    runtime: python31
    buildCommand: pip install -r requirements.txt
    startCommand: python run.py
    envVars:
      - key: MONGODB_URI
        scope: run
        value: <your-mongodb-atlas-uri>
      - key: SECRET_KEY
        scope: run
        value: <your-secret-key>
```

---

## License

Final Year Cybersecurity Project. Use for educational purposes.

---

## Support

For issues or questions:
1. Check the [Troubleshooting](#troubleshooting) section
2. Review MongoDB Atlas [documentation](https://docs.mongodb.com/atlas/)
3. Check Flask [documentation](https://flask.palletsprojects.com/)
