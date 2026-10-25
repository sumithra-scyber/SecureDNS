# SecureDNS — High-Performance DNS Resolver with Security Intelligence

A production-grade, asynchronous DNS caching resolver and threat intelligence monitoring platform developed in Python, FastAPI, PostgreSQL, and React.

---

## Architecture Overview

```text
                                 ┌────────────────────────┐
                                 │   Upstream DNS Server  │
                                 │      (e.g. 8.8.8.8)    │
                                 └───────────▲────────────┘
                                             │ (UDP forwarding)
┌──────────────┐   UDP / TCP Port 5300       │
│  DNS Client  │ ─────────────────────► ┌────┴─────────────────────────────┐
└──────────────┘                        │  Member 1: Core Resolver Engine │
                                        │  • Asynchronous Wire Parser     │
                                        │  • TTL-respecting LRU Cache     │
                                        │  • Token Bucket Rate Limiter    │
                                        │  • Domain Blocklist Enforcement │
                                        │  • Query Anomaly Inspector      │
                                        │  • Typed EventBus Emitter       │
                                        └────┬────────────────────────────┘
                                             │ (Synchronous EventBus.publish)
                                             ▼
                                        ┌─────────────────────────────────┐
                                        │  Member 2: Monitoring Subsystem │
                                        │  • Non-blocking asyncio.Queue   │
                                        │  • Background Batch Worker      │
                                        │  • PostgreSQL / SQLite Store    │
                                        │  • Alembic Migrations           │
                                        │  • FastAPI REST Engine (:8000)  │
                                        └────┬────────────────────────────┘
                                             │ (JSON REST / CORS)
                                             ▼
                                        ┌─────────────────────────────────┐
                                        │  Member 2: Frontend Console     │
                                        │  • React 18 + TypeScript + Vite │
                                        │  • Chart.js Query Timeline      │
                                        │  • Threat Distribution Doughnut │
                                        │  • Paginated Security Audit Log │
                                        └─────────────────────────────────┘
```

---

## Team Division of Responsibilities

- **Member 1 (Resolver Engine)**:
  - DNS wire format message parsing (`src/securedns/resolver/message.py`)
  - Asynchronous UDP forwarder (`src/securedns/resolver/forwarder.py`)
  - Thread-safe LRU cache with TTL expiration (`src/securedns/cache/ttl_cache.py`)
  - Security modules: Blocklist, Token Bucket Rate Limiter, Query Inspector (`src/securedns/security/`)
  - Async UDP and TCP listeners (`src/securedns/server.py`)
  - Typed event definitions and EventBus (`src/securedns/events.py`)

- **Member 2 (Monitoring & Intelligence Dashboard)**:
  - Non-blocking event ingestion pipeline with backpressure buffer (`src/securedns/monitoring/event_handler.py`)
  - Async PostgreSQL & SQLite persistence layer via SQLAlchemy 2.0 (`src/securedns/monitoring/database.py`, `models.py`)
  - Database schema migrations with Alembic (`migrations/`)
  - FastAPI monitoring REST API with Pydantic validation (`src/securedns/monitoring/app.py`, `routes/`, `schemas.py`)
  - Interactive React 18 + TypeScript + Vite monitoring console (`frontend/`)
  - Synthetic demo seed generator (`src/securedns/monitoring/seed.py`)
  - End-to-end integration and performance benchmark suite (`benchmarks/bench_monitoring.py`)

---

## Quick Start Guide

### 1. Prerequisites
- Python 3.11+
- Node.js 18+ and npm
- (Optional) Docker and Docker Compose

### 2. Setup Python Virtual Environment
```bash
# Clone the repository
git clone https://github.com/sumithra-scyber/SecureDNS.git
cd SecureDNS

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate       # On Linux/macOS
.venv\Scripts\activate          # On Windows

# Install project dependencies
pip install -e ".[dev,monitoring]"
```

### 3. Setup Frontend Dashboard
```bash
cd frontend
npm install
npm run build   # Verifies TypeScript compilation and bundle creation
cd ..
```

### 4. Run the Complete System
```bash
# Terminal 1: Run Resolver + Monitoring API together (Zero-config SQLite default)
python -m securedns.run_all

# Terminal 2: Run Frontend Development Server
cd frontend
npm run dev
```

Open your browser to:
- **Frontend Dashboard**: `http://localhost:5173`
- **FastAPI Interactive Docs**: `http://localhost:8000/docs`
- **Health Check**: `http://localhost:8000/api/health`
- **DNS Server Listening on**: `127.0.0.1:5300` (UDP + TCP)

---

## Testing & Quality Assurance

### Run All Automated Tests
```bash
pytest
```
*Current test suite: **50 tests passing (36 Member 1 tests + 14 Member 2 tests)** with 100% pass rate.*

### Run Cache & Monitoring Benchmarks
```bash
# Member 1 DNS cache benchmark
python benchmarks/bench_cache.py

# Member 2 event ingestion and API benchmark
python benchmarks/bench_monitoring.py
```

### Measured Performance Results:
- **Event Ingestion Queue**: >350,000 events/second (p50: 2.1 µs)
- **Database Persistence**: >2,500 events/second (batched)
- **API Health Check Latency**: p50 = 1.36 ms (p99 = 3.18 ms)
- **API Paginated Events Latency**: p50 = 3.90 ms (p99 = 11.80 ms)

---

## Docker Deployment

To launch the full containerized stack with PostgreSQL:
```bash
docker compose up --build -d
```
Services deployed:
- `postgres`: PostgreSQL 16 on port 5432
- `monitoring-api`: FastAPI REST API on port 8000
- `frontend`: Nginx serving production React app on port 5173

---

## Documentation
- [Monitoring Architecture](docs/MONITORING.md)
- [Viva & Exam Preparation Guide](docs/VIVA_GUIDE.md)
- [Frontend Documentation](frontend/README.md)
