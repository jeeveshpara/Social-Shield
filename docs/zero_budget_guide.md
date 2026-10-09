# Zero-Budget Operations Guide

SocialShield operates exclusively using zero-budget resources that require no credit card, no billing setup, and no paid service subscriptions.

## 1. Zero-Budget Threat Intelligence Feeds

| Provider | Purpose | Authentication | Cost |
| :--- | :--- | :--- | :--- |
| **URLhaus (abuse.ch)** | Malware and botnet URL blocklist | None (Direct public API) | $0.00 |
| **PhishTank** | Verified phishing database | Free registration key (optional) | $0.00 |
| **Cloudflare DoH** | DNS record resolution (A, AAAA, MX, NS, TXT) | Open standard RFC 8484 | $0.00 |
| **ICANN RDAP** | Domain registration age & registrar | Open standard RFC 7484 | $0.00 |

## 2. Zero-Budget AI & LLM Reasoning

SocialShield does not require paid OpenAI or Anthropic API accounts.

1. **Default: Autonomous Heuristic Engine**:
   - Executes locally on the backend server.
   - Requires $0.00 and zero internet API calls.
   - Generates complete MITRE ATT&CK mappings and incident containment plans.
2. **Optional Cloud Models (Free Tiers)**:
   - **Google AI Studio (Gemini 1.5 Flash)**: Completely free tier API key without billing requirement.
   - **Groq Cloud (LLaMA 3.1 8B)**: Free tier without credit card requirement.

## 3. Zero-Budget Hosting Options

| Component | Platform | Free Tier Specifications |
| :--- | :--- | :--- |
| **Backend** | [Render.com](https://render.com) | Free Web Service (512 MB RAM, configured via `render.yaml`) |
| **Frontend** | [Vercel](https://vercel.com) | Free Hobby Plan (Configured via `frontend/vercel.json`) |
| **Database** | [Neon.tech](https://neon.tech) / Render | Free Serverless PostgreSQL |
| **Local Deployment** | Docker Compose | Local multi-container stack |
