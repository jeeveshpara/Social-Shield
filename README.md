# 🛡️ SocialShield

> **A 100% free, zero-budget cybersecurity tool to detect scams, phishing links, and fake social media accounts in seconds.**

[![CI/CD Pipeline](https://github.com/your-username/SocialShield/actions/workflows/ci.yml/badge.svg)](https://github.com/your-username/SocialShield)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-brightgreen.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com)
[![React 19](https://img.shields.io/badge/React-19.0-61dafb.svg)](https://react.dev)
[![Tests Passing](https://img.shields.io/badge/Tests-27%2F27%20Passed-success.svg)](backend/tests)

---

## 📖 What is SocialShield? (In Plain English)

Have you ever received a suspicious DM, seen a crypto giveaway that seemed too good to be true, or wondered if a profile or link is legitimate? 

**SocialShield** is a defensive intelligence platform that investigates any **social media username** or **web link** and gives you a clear safety verdict:
- 🚨 **Is it a scam?** (Crypto doublers, fake job offers, advance-fee prizes, extortion)
- 🎣 **Is it a phishing site?** (Lookalike domains mimicking PayPal, Microsoft, Apple, or Binance)
- 🎭 **Is someone impersonating an official account?** (Detects fake VIPs, deceptive handles like `paypa1` or `elonmusk_official`, and invisible lookalike characters)
- 🤖 **What should you do?** (An AI Security Analyst explains the threat in simple terms and gives you step-by-step incident containment actions)

---

## 💎 The Zero-Budget Golden Rule

> **"No paid APIs. No billing required. No credit cards needed."**

Every feature in SocialShield is built using free, open public standards:
- **Free Malware & Phishing Feeds**: Uses [URLhaus](https://urlhaus.abuse.ch/) and [PhishTank](https://phishtank.org/).
- **Free Domain & DNS Checks**: Uses open DNS-over-HTTPS (Cloudflare DoH) and ICANN RDAP.
- **Free AI Reasoning**: Includes a built-in **Autonomous Cyber Analyst Engine** that runs 100% locally on your computer for free, with optional plug-and-play support for free-tier Google Gemini or Groq models.

---

## 🚀 Quick Start (Up & Running in 2 Minutes)

### Step 1: Clone the Repository
```bash
git clone https://github.com/your-username/SocialShield.git
cd SocialShield
```

### Step 2: Start the Backend (FastAPI)
```powershell
# In PowerShell:
cd backend
.\venv\Scripts\activate
pip install -r requirements.txt
pip install pytest httpx

# Start the API server
uvicorn app.main:app --reload --port 8000
```
*(The backend automatically creates the database tables and seeds demo accounts on first launch!)*

### Step 3: Start the Frontend (React + Vite)
Open a new terminal window:
```powershell
cd frontend
npm install
npm run dev
```

### Step 4: Open in Your Browser!
- **Web App**: [http://localhost:5173](http://localhost:5173)
- **API Swagger Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Health Check**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

---

## 🔑 Demo Login Accounts

SocialShield comes pre-configured with two user accounts ready for testing:

| Role | Username | Password | Permissions |
| :--- | :--- | :--- | :--- |
| **👑 Admin** | `admin` | `Admin@12345` | Full access: run scans, delete scans, view metrics |
| **🔍 Analyst** | `analyst` | `Analyst@12345` | Standard operator: run scans, view AI reports |

*(Tip: On the login page, you can click the quick-fill buttons to sign in with one click!)*

---

## 🔍 How SocialShield Works

When you enter a target (like `http://paypal-security-update.xyz/login.php` or `@elonmusk_official`), SocialShield runs it through four defensive engines in parallel:

```
    Your Input: Username or URL
               │
               ▼
  ┌─────────────────────────┐
  │  1. OSINT Engine        │ ──► Checks DNS, domain age, redirect hops, and cross-platform presence.
  └────────────┬────────────┘
               ▼
  ┌─────────────────────────┐
  │  2. Fraud Engine        │ ──► Scans for crypto doublers, job scams, phishing paths, and lookalikes.
  └────────────┬────────────┘
               ▼
  ┌─────────────────────────┐
  │  3. Risk Calibrator     │ ──► Calculates an explainable 0–100 Risk Score across 5 tiers.
  └────────────┬────────────┘
               ▼
  ┌─────────────────────────┐
  │  4. AI Security Analyst │ ──► Writes an executive report with MITRE ATT&CK codes & action steps.
  └─────────────────────────┘
```

---

## 📊 Understanding the Risk Score

SocialShield assigns an explainable **Risk Score from 0 to 100**:

| Score | Risk Level | Color | What It Means |
| :---: | :---: | :---: | :--- |
| **0 – 14** | **INFO / SAFE** | 🟢 Green | Clean target. No indicators of compromise or fraud detected. |
| **15 – 39** | **LOW** | 🔵 Blue | Minor anomalies (e.g. HTTP instead of HTTPS, unverified terms). |
| **40 – 64** | **MEDIUM** | 🟡 Yellow | Suspicious characteristics found (e.g. unverified brand mention, freshly registered domain). |
| **65 – 84** | **HIGH** | 🟠 Orange | Strong indicators of social engineering, scam wording, or typosquatting. |
| **85 – 100** | **CRITICAL** | 🔴 Red | Dangerous threat! Confirmed malware/phishing feed match or active credential harvester. |

---

## 🛠️ The 4 Core Intelligence Engines

### 1. OSINT Engine (`backend/app/services/osint/`)
- **Username Footprinting**: Probes public availability across Twitter/X, GitHub, Instagram, YouTube, TikTok, and LinkedIn without logging in.
- **Homoglyph & Cyrillic Detection**: Spots lookalike letters designed to deceive the human eye (e.g., using Cyrillic `а` instead of Latin `a` in `pаypal`).
- **Domain & DNS Intelligence**: Queries Cloudflare DNS-over-HTTPS for A, AAAA, MX, NS, and email security records (SPF/DMARC).
- **Domain Age Forensics**: Uses ICANN RDAP to determine domain registration age. Domains younger than 30 days are automatically flagged.
- **Redirect Tracer**: Follows URL shorteners (`bit.ly`, `tinyurl.com`) to reveal their true final destination.

### 2. Fraud Engine (`backend/app/services/fraud/`)
- **Scam Pattern Detector**: Identifies 6 major fraud categories:
  - Crypto doublers & giveaway drainers ("Send 1 ETH to receive 2 ETH")
  - Fake job & task investment scams ("Earn $500/day liking videos")
  - Advance-fee & fake lottery rewards
  - Romance / Pig Butchering investment traps
  - Fake tech support & extortion threats
  - Artificial urgency triggers ("Account suspended in 24 hours!")
- **Phishing Detector**: Measures Levenshtein edit-distance against high-value brands (`paypal`, `microsoft`, `apple`, `google`, `binance`, `coinbase`, `metamask`, `steam`, etc.) and flags deceptive subdomains (like `paypal.com.verify-user.xyz`).
- **High-Abuse TLD Scoring**: Penalizes suspicious top-level domains commonly used in disposable phishing (`.xyz`, `.top`, `.buzz`, `.icu`, `.tk`, etc.).

### 3. AI Security Analyst (`backend/app/services/ai_analyst/`)
- **Executive Threat Summary**: Translates raw forensic data into plain, easy-to-read English.
- **Threat Actor Profiling**: Identifies attacker intent, sophistication level (Low, Moderate, Advanced), and targeted demographic.
- **MITRE ATT&CK® Mapping**: Maps findings to standard security framework techniques (e.g., `T1566.002 Spearphishing Link`, `T1583.001 Acquire Domains`, `T1656 Impersonation`).
- **Actionable Containment Steps**: Gives immediate instructions to prevent loss (e.g., reset passwords, block DNS, report to registrar abuse contacts).

### 4. Security Hardening (`backend/app/services/security/`)
- **JWT & PBKDF2 Password Hashing**: Enterprise-grade password security using salted SHA-256 with 100,000 iterations.
- **Role-Based Access Control (RBAC)**: Enforces permissions for `admin`, `analyst`, and `viewer`.
- **SSRF Attack Protection**: Prevents attackers from using the scanner to probe your local network, loopback (`127.0.0.1`), or cloud metadata (`169.254.169.254`).
- **Prompt-Injection Defenses**: Sanitizes inputs to prevent malicious text from overriding or jailbreaking the AI analysis engine.
- **Rate Limiting**: Protects against automated spam and denial-of-service attempts.

---

## 🧪 Automated Testing (Sprint 7)

SocialShield includes a complete automated test suite covering unit tests, API tests, security hardening, and false-positive benchmarks.

Run all tests with one command:
```powershell
cd backend
.\venv\Scripts\python -m pytest -v tests/
```

### What the Tests Verify (27/27 Passing):
- ✅ **Unit Tests (`test_unit_engines.py`)**: Tests username entropy, homoglyph character matching, scam triggers, brand typosquatting, and risk calculations.
- ✅ **API Tests (`test_api_endpoints.py`)**: Tests user registration, login, JWT token auth, scan creation, history retrieval, and AI reports.
- ✅ **Security Tests (`test_security_hardening.py`)**: Tests that SSRF attacks against internal IPs are blocked, security headers are present, prompt-injection attacks are defanged, and non-admins cannot delete scans.
- ✅ **False-Positive Tests (`test_false_positives.py`)**: Tests benign everyday targets (`google.com`, `github.com`, ordinary usernames) to ensure they never trigger false high-risk alarms.

---

## 🐳 Easy Production Deployment (Docker Compose)

Want to run the complete stack (Database + Backend + Frontend) in production with Docker?

Run:
```bash
docker compose up --build -d
```

This starts:
1. **`socialshield-db`**: PostgreSQL 16 Alpine with automatic health checks.
2. **`socialshield-api`**: FastAPI backend with multi-worker support.
3. **`socialshield-web`**: Production React SPA served via Nginx with gzip compression and reverse proxying.

---

## ☁️ Zero-Budget Cloud Hosting (Render + Vercel)

SocialShield is ready for 100% free cloud deployment:

- **Backend (FastAPI)**: Deploy to [Render.com](https://render.com) using the included [`render.yaml`](render.yaml) blueprint (free tier).
- **Frontend (React)**: Deploy to [Vercel](https://vercel.com) using the included [`frontend/vercel.json`](frontend/vercel.json) (free tier).
- **Database**: Use a free PostgreSQL database from [Neon.tech](https://neon.tech) or Render.

---

## 📁 Project Directory Guide

```text
SocialShield/
├── backend/                         # FastAPI Python Application
│   ├── app/
│   │   ├── api/                    # API Endpoints (Auth, Scans)
│   │   ├── models/                 # Database Models (Scan, User)
│   │   ├── services/
│   │   │   ├── osint/             # OSINT Engine (Username, Domain, URL, Metadata)
│   │   │   ├── fraud/             # Fraud Engine (Scams, Phishing, Impersonation)
│   │   │   ├── ai_analyst/        # AI Cyber Analyst & MITRE ATT&CK Mappings
│   │   │   └── security/          # Security Hardening (JWT, RBAC, SSRF, Rate Limiting)
│   │   ├── database.py             # PostgreSQL SQLAlchemy Connection
│   │   └── main.py                 # FastAPI Gateway & Security Headers
│   ├── tests/                      # Pytest Automated Test Suite (27 tests)
│   ├── Dockerfile                  # Multi-stage production container
│   └── requirements.txt            # Python dependencies
│
├── frontend/                        # React 19 + TypeScript Frontend
│   ├── src/
│   │   ├── pages/
│   │   │   ├── LoginPage.tsx      # Authenticated JWT Login Page
│   │   │   ├── DashboardPage.tsx  # Security Dashboard & Scan Form
│   │   │   └── FindingsPage.tsx   # Detailed Forensic Report & AI Card
│   │   ├── styles/                 # Dark cyberpunk glassmorphism CSS
│   │   ├── api.ts                  # Axios client with JWT interceptor
│   │   └── types.ts                # TypeScript data interfaces
│   ├── Dockerfile                  # Nginx production container
│   ├── nginx.conf                  # Nginx reverse proxy configuration
│   └── vercel.json                 # Vercel zero-budget configuration
│
├── docs/                            # In-depth Architecture & Operations Guides
├── docker-compose.yml               # Complete local multi-container stack
├── render.yaml                      # Render free tier deployment blueprint
└── README.md                        # Master project documentation
```

---

## ❓ Frequently Asked Questions (FAQ)

<details>
<summary><b>1. Do I need to buy an OpenAI or Anthropic API key to use the AI Analyst?</b></summary>
<p>No! SocialShield comes with a built-in <b>Autonomous Cyber Analyst Engine</b> that runs 100% locally on your computer with zero API keys and zero cost. If you wish, you can optionally connect a free-tier Google Gemini or Groq key in your <code>.env</code> file, but it is completely optional.</p>
</details>

<details>
<summary><b>2. Does SocialShield hack or log into the accounts it inspects?</b></summary>
<p>No. SocialShield is strictly defensive. It only inspects publicly available information (such as DNS records, domain registration age, HTTP headers, and public profile existence) without performing unauthorized access or credential interception.</p>
</details>

<details>
<summary><b>3. What should I do if a scan shows HIGH or CRITICAL risk?</b></summary>
<p>Check the <b>Immediate Containment & Incident Response</b> section on the Findings page. Recommended steps typically include avoiding entering credentials, blocking the domain on your network/DNS, reporting the site to Google Safe Browsing, and submitting abuse notices to the hosting provider or registrar.</p>
</details>

---

## ⚖️ License & Ethical Disclaimer

SocialShield is released under the **MIT License**. It is designed solely for defensive cybersecurity research, fraud prevention, victim assistance, and educational use.