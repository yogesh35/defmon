# DefMon

DefMon is a SIEM/SOAR platform that classifies incoming web logs as `normal` or `malicious` and automates responses.

This project is now configured in **remote-only ingestion mode** by default:

- No synthetic/fake log generation in normal setup
- No local file collector stream unless explicitly enabled
- Expected log source is Linux VM(s) via sender API

## Run Locally (Docker)

1. Clone and enter project:

```bash
git clone https://github.com/yogesh35/defmon.git
cd defmon
```

2. Create env file:

```bash
cp .env.example .env
```

3. Start stack:

```bash
docker compose up --build -d
```

4. Run migrations/admin bootstrap:

```bash
docker compose exec defmon-api alembic upgrade head
docker compose exec defmon-api python -m defmon.bootstrap --username admin --password admin
```

5. Open services:

- Frontend: `http://localhost:3000`
- API docs: `http://localhost:8000/docs`
- Health: `http://localhost:8000/health`

## Linux VM Log Ingestion (Only Source)

### 1. Create a sender (Admin login required)

Create sender credentials via API:

```bash
curl -X POST "http://<DEFMON_HOST>:8000/api/senders" \
  -H "Authorization: Bearer <ADMIN_JWT>" \
  -H "Content-Type: application/json" \
  -d '{"name":"linux-vm-01","description":"Linux VM","allowed_ip":"<VM_IP>"}'
```

Save:

- `sender.id`
- `api_key`

### 2. Run the Linux forwarder on VM

Use `scripts/linux_log_forwarder.py` on the Linux machine:

```bash
python3 linux_log_forwarder.py \
  --api-base "http://<DEFMON_HOST>:8000" \
  --sender-id "<SENDER_ID>" \
  --sender-key "<SENDER_KEY>" \
  --log-path /var/log/nginx/access.log
```

You can repeat `--log-path` for multiple files.

### 3. Validate received logs

```bash
curl -H "Authorization: Bearer <JWT>" \
  "http://<DEFMON_HOST>:8000/api/logs/received?sender_id=<SENDER_ID>&limit=100"
```

Each entry includes:

- `classification` (`normal` or `malicious`)
- `is_malicious` (`true` or `false`)

## Important Settings

In `.env`:

- `ENABLE_LOCAL_COLLECTOR=false`
- `USE_SEED_LOGS=false`

In `config.yaml`:

- `app.enable_local_collector: false`
- `log_sources: []`

These ensure logs come only from Linux VM sender ingestion.

## Commands

```bash
make dev              # Start stack in foreground
make up               # Start stack detached
make stop             # Stop stack
make clean            # Stop and remove volumes
make migrate          # Run alembic upgrade
make bootstrap-admin  # Create/update admin user
make test             # Run tests in container
```
# DefMon

Real-time web security monitoring and response platform.

DefMon ingests real access logs (Apache/Nginx), classifies each event as `normal` or `malicious`, generates alerts, executes SOAR playbooks, and exposes API + dashboard views for SOC operations.

## What Is Included

- Backend API: FastAPI (`defmon/`)
- Detection engine: rule + threshold + behavioral (`defmon/detection/engine.py`)
- SOAR actions/playbooks (`defmon/soar/`)
- Remote sender ingestion (`/api/senders/ingest`)
- Frontend dashboard: React + Vite (`frontend/`)
- Database migrations: Alembic (`alembic/versions/`)
- Linux VM log forwarder script (`scripts/linux_log_forwarder.py`)
- Original log sender (`scripts/original_log_sender.py`)

## Run On Any Machine

### Option A: Docker (Recommended)

Prerequisites:

- Docker
- Docker Compose

Steps:

1. Clone repository

```bash
git clone https://github.com/yogesh35/defmon.git
cd defmon
```

2. Create environment file

```bash
cp .env.example .env
```

3. Start all services

```bash
docker compose up --build -d
```

This starts:

- PostgreSQL on `localhost:${POSTGRES_HOST_PORT}` (default `15432`)
- DefMon API on `http://localhost:${API_HOST_PORT}` (default `18000`)
- Frontend on `http://localhost:${FRONTEND_HOST_PORT}` (default `13000`)

These host ports are configurable in `.env` so DefMon can run alongside other Docker projects.

4. Create default admin account (first run)

```bash
docker compose exec defmon-api python -m defmon.seed
```

Default login:

- Username: `admin`
- Password: `admin`

5. Verify

```bash
curl http://localhost:18000/health
```

### Option B: Local Python + Node

Prerequisites:

- Python 3.11+
- Node.js 20+
- PostgreSQL 15+

Backend:

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
alembic upgrade head
python -m defmon.seed
uvicorn defmon.main:app --host 0.0.0.0 --port 8000
```

Frontend (new terminal):

```bash
cd frontend
npm ci
npm run dev -- --host
```

## Key Endpoints

- Health: `GET /health`
- API docs: `GET /docs`
- Login: `POST /api/auth/login`
- Alerts: `GET /api/alerts`
- Incidents: `GET /api/incidents`
- Received logs: `GET /api/logs/received`
- Sender management: `POST /api/senders` and related endpoints
- Remote ingest: `POST /api/senders/ingest?sender_id=<id>&sender_key=<key>`

## Real Linux Log Ingestion

1. Create sender from admin API (`/api/senders`) and save `sender.id` + `api_key`
2. On Linux VM, run forwarder:

```bash
python3 scripts/linux_log_forwarder.py \
  --api-base "http://<DEFMON_HOST>:8000" \
  --sender-id "<SENDER_ID>" \
  --sender-key "<SENDER_KEY>" \
  --log-path /var/log/nginx/access.log
```

If DefMon receiver is running on Windows (WSL/Linux VM sender), use Windows receiver mode:

```bash
python3 scripts/linux_log_forwarder.py \
  --windows-receiver \
  --sender-id "<SENDER_ID>" \
  --sender-key "<SENDER_KEY>" \
  --log-path /var/log/nginx/access.log
```

Optional Windows mode overrides:

- `--windows-host <WINDOWS_IP>` when auto-detection cannot resolve the receiver
- `--receiver-port <PORT>` if API is not exposed on `8000`
- `DEFMON_WINDOWS_HOST=<WINDOWS_IP>` for a persistent default host

3. Validate classification:

```bash
curl -H "Authorization: Bearer <JWT>" \
  "http://<DEFMON_HOST>:8000/api/logs/received?limit=50&sender_id=<SENDER_ID>"
```

Each stored event includes:

- `classification`: `normal` or `malicious`
- `is_malicious`: `true`/`false`

## Original Log Sender (Real Logs)

Send real access log lines to DefMon. The sender logs in as admin, creates a sender identity,
reads real log files, and forwards them to `/api/senders/ingest`.

```bash
python3 scripts/original_log_sender.py \
  --api-base "http://localhost:18000" \
  --username "admin" \
  --password "admin" \
  --log-path /var/log/nginx/access.log \
  --log-path /var/log/apache2/access.log \
  --lines-per-file 300 \
  --batch-size 100
```

For continuous generation until you stop it, add:

```bash
--continuous --lines-per-cycle 5 --batch-size 5 --repeat-delay-seconds 0.5 --malicious-rate 0.25
```

Per batch, the sender prints DefMon-classified counts:

- `malicious_lines`
- `normal_lines`

## Common Commands

```bash
make dev        # docker compose up --build
make stop       # docker compose down
make clean      # docker compose down -v
make migrate    # run alembic migrations in api container
make test       # run pytest in api container
make test-local # run pytest locally
make send-real-logs # send 5 logs every 0.5s, injecting random malicious lines (Ctrl+C to stop)
```

## Notes

- `docker-compose.yml` is now aligned to the current `defmon/` codebase.
- If using AbuseIPDB, set `ABUSEIPDB_KEY` in `.env`.
- Prometheus metrics are exposed by backend on `/metrics`.
# Defmon — Website Security Monitoring & Automated Response

A real-time website security monitoring and automated response framework integrating **SIEM** (Security Information and Event Management) and **SOAR** (Security Orchestration, Automation, and Response) for web application defense.

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Web Server Logs │───▶│  Log Collector   │───▶│  Normalizer     │
│  (Apache/Nginx)  │    │  (File Watcher)  │    │  (Parser)       │
└─────────────────┘    └──────────────────┘    └────────┬────────┘
                                                         │
                       ┌──────────────────┐              ▼
                       │ Threat Intel Feed│     ┌─────────────────┐
                       │ (IP Reputation)  │────▶│  Event Store    │
                       └──────────────────┘     │  (SQLite)       │
                                                └────────┬────────┘
                                                         │
┌─────────────────┐    ┌──────────────────┐              ▼
│  SOAR Engine     │◀───│  Detection       │◀────────────┘
│  (Playbooks)     │    │  Engine (Rules)  │
└────────┬────────┘    └──────────────────┘
         │
         ▼
┌─────────────────┐                           ┌─────────────────┐
│ Response Actions │                           │  SOC Dashboard  │
│ - Block IP       │                           │  (Web UI)       │
│ - Lock Account   │                           │  - Login/Auth   │
│ - Blacklist      │                           │  - Live Feed    │
│ - Alert/Notify   │                           │  - Charts/Graphs│
│ - Create Ticket  │                           │  - Geo Map      │
└─────────────────┘                           │  - Reports      │
                                              └─────────────────┘
```

## Features

### SIEM — Detection Engine
- Real-time log parsing & normalization (Apache/Nginx/Auth/App)
- Rule-based + threshold-based + behavioral detection
- 8 attack detection rules with MITRE ATT&CK mapping
- Risk scoring and alert deduplication

### SOAR — Automated Response
- Automated IP blocking (firewall orchestration)
- **Compromised account locking**
- Dynamic blacklist management
- Incident ticket generation
- Alert notifications (console, log, Slack, email, syslog CEF)
- Response playbooks with severity-based automation
- Full response audit trail

### Threat Intelligence
- IP reputation database with malicious/suspicious classification
- Threat indicator tags (scanner, bruteforce, tor_exit, botnet, etc.)
- Alert enrichment with threat context
- Manual indicator management via API

### User Authentication & Access Control
- JWT-based authentication
- Role-based access: **Admin** and **Analyst**
- Login page with session management
- User management API (admin only)

### SOC Dashboard
- **Login page** with role-based access
- Live attack feed (WebSocket)
- Alert list with severity color-coding and CSV export
- Top attacking IPs with threat intelligence lookup
- Geo-location attack map (Leaflet.js)
- Attack type distribution (Chart.js)
- Timeline graphs and severity breakdown
- SOAR response actions log
- **Locked accounts** management panel
- **Threat intelligence** panel with IP lookup
- Incident management with CSV export
- Log search & filter

### Reporting
- Alerts export (JSON/CSV)
- Incidents export (JSON/CSV)
- Security summary report with threat intelligence stats

## Quick Start

### Docker (Recommended)
```bash
docker-compose up --build
```

### Manual
```bash
pip install -r requirements.txt
# Terminal 1: Start backend
uvicorn defmon.main:app --host 0.0.0.0 --port 8000
# Terminal 2: Send real logs
python3 scripts/original_log_sender.py --api-base http://localhost:18000 --log-path /var/log/nginx/access.log
# Open http://localhost:13000 in browser
```

### Default Credentials
| Username | Password | Role |
|----------|----------|------|
| admin | admin | Admin |

## Sending Real Logs
```bash
python3 scripts/original_log_sender.py --api-base http://localhost:18000 --log-path /var/log/nginx/access.log
# With options:
python3 scripts/original_log_sender.py --api-base http://localhost:18000 --log-path /var/log/nginx/access.log --lines-per-file 1000 --batch-size 200
```

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Login and get JWT token |
| GET | `/api/auth/me` | Get current user info |
| POST | `/api/auth/users` | Create user (admin only) |
| GET | `/api/auth/users` | List users (admin only) |

### Alerts & Incidents
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

### SOAR & Response
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/blocked-ips` | List blocked IPs |
| DELETE | `/api/blocked-ips/{ip}` | Unblock IP |
| GET | `/api/locked-accounts` | List locked accounts |
| DELETE | `/api/locked-accounts/{id}` | Unlock account |
| GET | `/api/response-actions` | Response action history |

### Threat Intelligence
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/threat-intel` | Get all threat indicators & stats |
| GET | `/api/threat-intel/lookup/{ip}` | Look up IP reputation |
| POST | `/api/threat-intel/indicators` | Add threat indicator |

### Reporting
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/reports/alerts?format=csv` | Export alerts report |
| GET | `/api/reports/incidents?format=csv` | Export incidents report |
| GET | `/api/reports/summary` | Security summary report |

### Live Feed
| Method | Endpoint | Description |
|--------|----------|-------------|
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

## SOAR Response Playbooks

| Severity | Actions |
|----------|---------|
| **Critical** | Notify → Block IP → Blacklist → Lock Account → Create Incident |
| **High** | Notify → Block IP → Lock Account → Create Incident |
| **Medium** | Notify → Create Incident |
| **Low** | Notify |

## Folder Structure
```
defmon/
├── backend/
│   ├── main.py              # FastAPI app entry
│   ├── core/
│   │   ├── auth.py          # JWT authentication & RBAC
│   │   ├── config.py        # Configuration
│   │   ├── database.py      # DB setup & models
│   │   └── models.py        # SQLAlchemy models (7 tables)
│   ├── api/
│   │   ├── routes.py        # API endpoints
│   │   └── websocket.py     # WebSocket live feed
│   ├── detection/
│   │   ├── engine.py        # Detection engine
│   │   └── rules.py         # Detection rules
│   ├── soar/
│   │   ├── playbooks.py     # Response playbooks
│   │   ├── actions.py       # Response actions (block, lock, notify)
│   │   └── notifications.py # Multi-channel notifications
│   ├── collectors/
│   │   └── log_collector.py # Log ingestion
│   └── utils/
│       ├── parser.py        # Log parser/normalizer
│       ├── geoip.py         # GeoIP lookup
│       └── threat_intel.py  # Threat intelligence feed
├── frontend/
│   └── static/
│       ├── index.html       # Login + SOC Dashboard
│       ├── css/dashboard.css
│       └── js/dashboard.js
├── scripts/
│   ├── linux_log_forwarder.py
│   └── original_log_sender.py
├── data/
│   ├── logs/                # Log files
│   ├── db/                  # SQLite database
│   └── threat_intel/        # Threat feed data
├── docker/
│   └── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## Tech Stack
- **Backend**: Python 3.11+ / FastAPI / SQLAlchemy / JWT
- **Frontend**: HTML5 / CSS3 / JavaScript / Chart.js / Leaflet.js
- **Database**: SQLite (swappable to PostgreSQL)
- **Authentication**: JWT + bcrypt password hashing
- **Containerization**: Docker + Docker Compose
