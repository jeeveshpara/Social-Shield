# 🛡️ SocialShield

**Defensive Cybersecurity & Cyber-Fraud Intelligence Platform**

SocialShield is an open-source, defensive cybersecurity platform engineered to detect social engineering attacks, account impersonation, deceptive infrastructure, and financial cyber-fraud using open public signals and threat intelligence.

---

## 💡 Zero-Budget Principle

SocialShield is architected strictly under a **zero-budget philosophy**:
- **No Paid APIs**: Relies on open RFC standards (DNS-over-HTTPS via Cloudflare, ICANN RDAP for domain age), open malware feeds (URLhaus by abuse.ch), and free phishing databases (PhishTank).
- **No Billing Requirements**: Zero services that require credit cards, trial billing, or payment methods.
- **Built-in Autonomous AI Security Analyst**: Operates 100% locally and offline without external API keys, with optional plug-and-play support for free-tier cloud models (Google Gemini Free Tier, Groq Free Tier).

---

## 🚀 Development Roadmap & Delivery Status

| Sprint | Milestone | Status | Key Deliverables |
| :--- | :--- | :---: | :--- |
| **Sprint 1** | **Project Setup** | ✅ Complete | GitHub repository, Python 3.12+ environment, FastAPI, React 19 + TypeScript, PostgreSQL, environment variables. |
| **Sprint 2** | **Dashboard** | ✅ Complete | JWT login, security metrics dashboard, live scan form, real-time scan history table, forensic findings report page. |
| **Sprint 3** | **OSINT Engine** | ✅ Complete | Multi-platform username footprinting, Shannon entropy, homoglyph detection, DoH DNS intelligence, ICANN RDAP domain age, HTTP redirect hop tracer, OpenGraph metadata extraction. |
| **Sprint 4** | **Fraud Engine** | ✅ Complete | Multi-category scam detectors (crypto doubler/drainer, task scams, advance fee, pig butchering, tech support extortion), phishing & brand typosquatting heuristics, high-abuse TLD scoring, impersonation detection, calibrated multi-factor risk scoring (0–100). |
| **Sprint 5** | **AI Security Analyst** | ✅ Complete | Autonomous Cyber Threat Intelligence Analyst, MITRE ATT&CK® matrix mapping, threat actor profiling, evidence correlation, containment guidance, zero-budget cloud LLM connectors (Gemini / Groq) with local offline fallback. |
| **Sprint 6** | **Security Hardening** | ✅ Complete | Salted PBKDF2 password hashing, JWT bearer tokens, RBAC (`admin`, `analyst`, `viewer`), thread-safe sliding window rate limiting, SSRF guard blocking private/loopback/cloud metadata ranges, prompt-injection defense with input defanging, security headers (`nosniff`, `DENY`, `HSTS`). |
| **Sprint 7** | **Testing** | ✅ Complete | 27 automated tests passing: Unit tests, API endpoint tests, Security hardening tests, False-positive benchmark tests. |
| **Sprint 8** | **Deployment** | ✅ Complete | Multi-stage Dockerfiles (Backend & Frontend), Nginx SPA reverse proxy with gzip, Docker Compose stack with PostgreSQL 16 healthchecks, GitHub Actions CI/CD pipeline, `/api/metrics` operational monitoring. |

---

## 🏛️ System Architecture

```
                               ┌────────────────────────────────────────────────────────┐
                               │                    User / Analyst                      │
                               └───────────────────────────┬────────────────────────────┘
                                                           │
                                                           ▼
                               ┌────────────────────────────────────────────────────────┐
                               │       Frontend: React 19 + TypeScript + Vite           │
                               │      (Dark Cyberpunk UI, Glassmorphism, Risk Gauges)   │
                               └───────────────────────────┬────────────────────────────┘
                                                           │ JWT Bearer / REST API
                                                           ▼
                               ┌────────────────────────────────────────────────────────┐
                               │              FastAPI Defensive Gateway                 │
                               │  - Security Headers (CSP, HSTS, X-Frame-Options)       │
                               │  - Sliding Window Rate Limiting                        │
                               │  - SSRF Protection Filter                              │
                               │  - RBAC & JWT Authentication                           │
                               └───────────┬────────────────────────────────┬───────────┘
                                           │                                │
                 ┌─────────────────────────┴──────────┐          ┌──────────┴───────────────┐
                 │                                    │          │                          │
                 ▼                                    ▼          ▼                          ▼
   ┌───────────────────────────┐        ┌───────────────────────────┐        ┌───────────────────────────┐
   │    Sprint 3: OSINT Engine │        │   Sprint 4: Fraud Engine  │        │ Sprint 5: AI Analyst      │
   │  - Username footprinting  │        │  - Scam heuristics        │        │  - MITRE ATT&CK Mapping   │
   │  - Homoglyph detection    │        │  - Phishing & Typosquats  │        │  - Threat Actor Profiling │
   │  - Cloudflare DoH DNS     │        │  - Impersonation cues     │        │  - Evidence Synthesis     │
   │  - ICANN RDAP Domain Age  │        │  - Calibrated Risk Scorer │        │  - Incident Containment   │
   │  - URL trace & Threat Feed│        └───────────────────────────┘        └───────────────────────────┘
   └───────────────────────────┘                      │
                 │                                    ▼
                 └──────────────────────► ┌───────────────────────────┐
                                          │  PostgreSQL 16 Storage    │
                                          │  - Scans & Evidence JSON  │
                                          │  - Users & RBAC Roles     │
                                          └───────────────────────────┘
```

---

## 🧪 Testing Suite (Sprint 7)

SocialShield includes a comprehensive test suite executed with `pytest`:

```bash
cd backend
.\venv\Scripts\python -m pytest -v tests/
```

Test coverage includes:
1. **Unit Tests (`test_unit_engines.py`)**: Normalization, Shannon entropy, homoglyph character analysis, scam keyword regexes, Levenshtein brand distance, calibrated risk scoring.
2. **API Tests (`test_api_endpoints.py`)**: End-to-end endpoint tests for health, metrics, registration, login, profile, scan lifecycle, and AI report generation.
3. **Security Hardening Tests (`test_security_hardening.py`)**: Verification of SSRF blocks against `127.0.0.1`, `localhost`, `169.254.169.254`, `192.168.1.1`, security response headers, prompt injection defanging, and admin RBAC enforcement.
4. **False-Positive Tests (`test_false_positives.py`)**: Benchmarking benign targets (`google.com`, `github.com`, legitimate usernames) to guarantee zero false-positive high-risk alarms, while confirming accurate risk escalation on active phishing samples.

---

## ⚡ Quick Start (Development)

### 1. Prerequisites
- Python 3.12+
- Node.js 20+
- PostgreSQL database

### 2. Backend Setup
```bash
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
pip install pytest httpx

# Configure environment
cp ../.env.example .env
# Edit .env with your DATABASE_URL

# Start backend server
uvicorn app.main:app --reload --port 8000
```

Default seeded credentials (created on startup):
- **Admin**: `admin` / `Admin@12345`
- **Analyst**: `analyst` / `Analyst@12345`

### 3. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Open [http://localhost:5173](http://localhost:5173) in your browser.

---

## 🐳 Production Deployment (Docker Compose)

Run the full production stack with a single command:

```bash
docker-compose up --build -d
```

Services initialized:
- `socialshield-db`: PostgreSQL 16 on port `5432` with automated healthchecks.
- `socialshield-api`: FastAPI production app on port `8000` with 2 workers.
- `socialshield-web`: React production SPA served by Nginx on port `80` with reverse proxying and security headers.

---

## 📡 API Reference

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :---: |
| `GET` | `/health` | Liveness probe & database connectivity | No |
| `GET` | `/api/metrics` | Observability metrics (scans, users, uptime) | No |
| `POST` | `/api/auth/register` | Register new user account | No (Rate-limited) |
| `POST` | `/api/auth/login` | Authenticate user & return JWT token | No (Rate-limited) |
| `GET` | `/api/auth/me` | Fetch authenticated user profile | Yes (Bearer) |
| `POST` | `/api/scans/` | Execute comprehensive OSINT + Fraud scan | No (Rate-limited & SSRF-guarded) |
| `GET` | `/api/scans/` | List historical scan records | No |
| `GET` | `/api/scans/{id}` | Retrieve individual scan details & evidence | No |
| `GET` | `/api/scans/{id}/analyst` | Retrieve AI Security Analyst report | No |
| `DELETE` | `/api/scans/{id}` | Delete scan record | Yes (`admin` role) |

---

## ⚖️ Security & Ethical Disclaimer

SocialShield is designed exclusively for authorized security research, fraud prevention, victim assistance, and defensive cybersecurity operations. It does not perform active intrusion, credential interception, or non-public data harvesting.