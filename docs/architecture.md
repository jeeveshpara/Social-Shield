# SocialShield Architecture Guide

## 1. Overview
SocialShield is an open-source, defensive cybersecurity and cyber-fraud intelligence platform designed to assess social accounts, public domain infrastructure, and URLs without relying on paid APIs or invasive techniques.

## 2. Multi-Engine Architecture

### A. OSINT Engine (`backend/app/services/osint/`)
- **Username Footprinting**: Evaluates handle complexity via Shannon entropy, visual lookalikes using Cyrillic/Greek homoglyphs, and probes public existence across major platforms without authentication.
- **Domain & DNS Intelligence**: Queries RFC-compliant DNS-over-HTTPS (DoH) via Cloudflare for A, AAAA, MX, NS, TXT, SPF, and DMARC records.
- **RDAP Domain Forensics**: Queries ICANN RDAP endpoints to calculate domain registration age, flagging fresh domains (<30 days old).
- **URL & Redirection Analysis**: Unrolls shorteners (`bit.ly`, `t.co`, etc.) and traces redirection hop chains to expose hidden destinations.

### B. Fraud Engine (`backend/app/services/fraud/`)
- **Scam Heuristics**: Detects crypto giveaways/doublers, fake task scams, advance fee/lottery schemes, romance investment (pig butchering), and tech support extortion.
- **Phishing Detection**: Employs Levenshtein distance against high-value target brands to identify typosquatting and combo-squatting, evaluates high-abuse TLDs, and identifies credential harvesting paths.
- **Impersonation Signals**: Flags authority-claiming handles (`official`, `support`, `verified`) and VIP mimicry.
- **Calibrated Multi-Factor Risk Scoring**: Synthesizes weighted dimensions into a 0–100 score across 5 security tiers (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

### C. AI Security Analyst (`backend/app/services/ai_analyst/`)
- **Autonomous Heuristic Engine**: 100% free, offline, deterministic reasoning engine that maps threats to MITRE ATT&CK techniques, profiles threat actors, synthesizes correlated evidence, and generates containment steps.
- **Zero-Budget Cloud LLM Connector**: Plug-and-play support for Google Gemini Free Tier or Groq Free Tier when API keys are supplied.

### D. Security Hardening (`backend/app/services/security/`)
- **Authentication**: Salted PBKDF2-HMAC-SHA256 password hashing with signed JWT bearer tokens.
- **RBAC**: Role-Based Access Control (`admin`, `analyst`, `viewer`).
- **Rate Limiting**: Sliding window in-memory limiter guarding against brute-force and scraping.
- **SSRF Protection**: Strict filtering blocking access to loopback (`127.0.0.1`), private networks, and cloud metadata (`169.254.169.254`).
- **Prompt Injection Defense**: Detection and defanging of adversarial jailbreak patterns.
