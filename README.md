# Mini SIEM + SOAR Platform

A production-style Security Information & Event Management (SIEM) + Security Orchestration, Automation & Response (SOAR) platform.

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Log Sources     │───▶│  Log Collector   │───▶│  Normalizer     │
│  (Simulator)     │    │  (File Watcher)  │    │  (Parser)       │
└─────────────────┘    └──────────────────┘    └────────┬────────┘
                                                         │
                                                         ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  SOAR Engine     │◀───│  Detection       │◀───│  Event Store    │
│  (Playbooks)     │    │  Engine (Rules)  │    │  (SQLite)       │
└────────┬────────┘    └──────────────────┘    └─────────────────┘
         │                                              │
         ▼                                              ▼
┌─────────────────┐                           ┌─────────────────┐
│  Response Actions│                           │  SOC Dashboard  │
│  - Block IP      │                           │  (Web UI)       │
│  - Blacklist     │                           │  - Live Feed    │
│  - Alert/Notify  │                           │  - Charts/Graphs│
│  - Ticket        │                           │  - Geo Map      │
└─────────────────┘                           └─────────────────┘
```

## Features

### SIEM
- Real-time log parsing & normalization (Apache/Nginx/Auth)
- Rule-based + threshold-based + behavioral detection
- 8+ attack detection rules (SQLi, XSS, brute force, dir traversal, etc.)
- MITRE ATT&CK mapping
- Risk scoring

### SOAR
- Automated IP blocking (firewall simulation)
- Dynamic blacklist management
- Incident ticket generation
- Alert notifications (Slack/email simulation)
- Response playbooks with severity levels
- Full response audit trail

### SOC Dashboard
- Live attack feed (WebSocket)
- Alert list with severity color-coding
- Top attacking IPs
- Geo-location map (Leaflet.js)
- Attack type distribution (Chart.js)
- Timeline graphs
- Response actions log
- Search & filter

## Quick Start

### Docker (Recommended)
```bash
docker-compose up --build
```

### Manual
```bash
pip install -r requirements.txt
# Terminal 1: Start backend
python -m backend.main
# Terminal 2: Start log simulator
python -m simulator.generate_logs
# Open http://localhost:8000 in browser
```

## Simulating Attacks
```bash
python -m simulator.generate_logs
# Or with options:
python -m simulator.generate_logs --rate fast --duration 300
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/alerts` | List alerts with filters |
| GET | `/api/alerts/{id}` | Get alert detail |
| PATCH | `/api/alerts/{id}` | Update alert status/notes |
| GET | `/api/incidents` | List incidents |
| GET | `/api/incidents/{id}` | Get incident detail |
| PATCH | `/api/incidents/{id}` | Update incident |
| GET | `/api/logs` | Search/filter logs |
| GET | `/api/stats` | Dashboard statistics |
| GET | `/api/blocked-ips` | List blocked IPs |
| DELETE | `/api/blocked-ips/{ip}` | Unblock IP |
| GET | `/api/response-actions` | Response action history |
| WS | `/ws/live-feed` | Live attack/alert feed |

## Detection Rules

| Rule | MITRE ATT&CK | Severity |
|------|--------------|----------|
| SQL Injection | T1190 | Critical |
| XSS Attempt | T1189 | High |
| Directory Traversal | T1083 | High |
| Brute Force | T1110 | High |
| 404 Scanning | T1595 | Medium |
| High Request Rate | T1498 | Medium |
| Suspicious User Agent | T1071 | Low |
| Blacklisted IP | — | Critical |

## Folder Structure
```
mini-siem-soar/
├── backend/
│   ├── main.py              # FastAPI app entry
│   ├── core/
│   │   ├── config.py        # Configuration
│   │   ├── database.py      # DB setup & models
│   │   └── models.py        # SQLAlchemy models
│   ├── api/
│   │   ├── routes.py        # API endpoints
│   │   └── websocket.py     # WebSocket live feed
│   ├── detection/
│   │   ├── engine.py        # Detection engine
│   │   └── rules.py         # Detection rules
│   ├── soar/
│   │   ├── playbooks.py     # Response playbooks
│   │   └── actions.py       # Response actions
│   ├── collectors/
│   │   └── log_collector.py # Log ingestion
│   └── utils/
│       ├── parser.py        # Log parser/normalizer
│       └── geoip.py         # GeoIP lookup
├── frontend/
│   └── static/
│       ├── index.html        # SOC Dashboard
│       ├── css/dashboard.css
│       └── js/dashboard.js
├── simulator/
│   └── generate_logs.py     # Attack log simulator
├── data/
│   ├── logs/                # Log files
│   └── db/                  # SQLite database
├── docker/
│   └── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## Tech Stack
- **Backend**: Python 3.11+ / FastAPI / SQLAlchemy
- **Frontend**: HTML5 / CSS3 / JavaScript / Chart.js / Leaflet.js
- **Database**: SQLite (swappable to PostgreSQL)
- **Containerization**: Docker + Docker Compose
