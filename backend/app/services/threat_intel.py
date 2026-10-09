"""
Threat intelligence lookups using zero-budget public feeds.

Providers used:
  - URLhaus (abuse.ch)  — malware / botnet URLs, no key required
  - PhishTank           — phishing URLs, free API key (no card required)

Both providers are checked in sequence.  The most severe result wins.
"""

import os
import time
from collections import deque
from threading import Lock

import httpx
from dotenv import load_dotenv

load_dotenv()

# ── URLhaus ──────────────────────────────────────────────────────────────────
URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"

# ── PhishTank ─────────────────────────────────────────────────────────────────
PHISHTANK_ENDPOINT = "https://checkurl.phishtank.com/checkurl/"

# ── Shared settings ───────────────────────────────────────────────────────────
TIMEOUT_SECONDS = float(os.getenv("THREAT_INTEL_TIMEOUT_SECONDS", "6"))
MAX_CALLS_PER_MINUTE = int(os.getenv("THREAT_INTEL_MAX_CALLS_PER_MINUTE", "30"))

_call_times: deque = deque()
_rate_lock = Lock()


def _reserve_call() -> bool:
    """Enforce a per-process rate limit across all outgoing provider calls."""
    now = time.monotonic()
    with _rate_lock:
        while _call_times and now - _call_times[0] >= 60:
            _call_times.popleft()
        if len(_call_times) >= MAX_CALLS_PER_MINUTE:
            return False
        _call_times.append(now)
        return True


def _urlhaus_lookup(url: str, client: httpx.Client) -> dict:
    """
    Query URLhaus for a URL.
    Returns a normalised result dict:
      { status: 'matched'|'no_match'|'unknown', provider, threat_types, message }
    """
    try:
        response = client.post(
            URLHAUS_ENDPOINT,
            data={"url": url},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        response.raise_for_status()
        data = response.json()

        query_status = data.get("query_status", "")

        if query_status == "is_listed":
            tags = data.get("tags") or []
            threat = data.get("threat", "malware")
            return {
                "status": "matched",
                "provider": "URLhaus (abuse.ch)",
                "threat_types": [threat] + [t for t in tags if t != threat],
                "message": "URLhaus flagged this URL as malicious.",
            }

        if query_status == "no_results":
            return {
                "status": "no_match",
                "provider": "URLhaus (abuse.ch)",
                "threat_types": [],
                "message": "URLhaus found no records for this URL.",
            }

        # query_status == "invalid_url" or unexpected
        return {
            "status": "unknown",
            "provider": "URLhaus (abuse.ch)",
            "threat_types": [],
            "message": f"URLhaus returned query_status={query_status!r}.",
        }

    except (httpx.TimeoutException, httpx.RequestError):
        return {
            "status": "unknown",
            "provider": "URLhaus (abuse.ch)",
            "threat_types": [],
            "message": "URLhaus request timed out or failed.",
        }
    except (httpx.HTTPStatusError, ValueError, KeyError):
        return {
            "status": "unknown",
            "provider": "URLhaus (abuse.ch)",
            "threat_types": [],
            "message": "URLhaus returned an unusable response.",
        }


def _phishtank_lookup(url: str, client: httpx.Client) -> dict:
    """
    Query PhishTank for a URL.
    Uses the free JSON API (no-key path returns useful results;
    optional PHISHTANK_API_KEY env var raises the rate limit).
    """
    api_key = os.getenv("PHISHTANK_API_KEY", "").strip()

    form_data: dict = {
        "url": url,
        "format": "json",
    }
    if api_key:
        form_data["app_key"] = api_key

    try:
        response = client.post(
            PHISHTANK_ENDPOINT,
            data=form_data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "SocialShield/0.2 phishtank-lookup",
            },
        )
        response.raise_for_status()
        data = response.json()

        results = data.get("results", {})

        if results.get("in_database") and results.get("valid"):
            return {
                "status": "matched",
                "provider": "PhishTank",
                "threat_types": ["phishing"],
                "message": "PhishTank confirmed this URL as a phishing site.",
            }

        if results.get("in_database") and not results.get("valid"):
            return {
                "status": "no_match",
                "provider": "PhishTank",
                "threat_types": [],
                "message": "PhishTank has this URL but it is no longer valid.",
            }

        return {
            "status": "no_match",
            "provider": "PhishTank",
            "threat_types": [],
            "message": "PhishTank found no records for this URL.",
        }

    except (httpx.TimeoutException, httpx.RequestError):
        return {
            "status": "unknown",
            "provider": "PhishTank",
            "threat_types": [],
            "message": "PhishTank request timed out or failed.",
        }
    except (httpx.HTTPStatusError, ValueError, KeyError):
        return {
            "status": "unknown",
            "provider": "PhishTank",
            "threat_types": [],
            "message": "PhishTank returned an unusable response.",
        }


def lookup_url(url: str) -> dict:
    """
    Public interface — check URL reputation without fetching the destination.

    Queries URLhaus first (no API key needed), then PhishTank.
    Returns the most severe result.  Contract is identical to the former
    Google Web Risk wrapper so the callers in api/scans.py need no changes.
    """
    if not _reserve_call():
        return {
            "status": "unknown",
            "provider": "URLhaus + PhishTank",
            "threat_types": [],
            "message": "Local provider rate limit reached; try again shortly.",
        }

    timeout = httpx.Timeout(TIMEOUT_SECONDS)

    with httpx.Client(timeout=timeout) as client:
        urlhaus = _urlhaus_lookup(url, client)

        # Short-circuit: a confirmed match is the highest severity possible.
        if urlhaus["status"] == "matched":
            return urlhaus

        phishtank = _phishtank_lookup(url, client)

        if phishtank["status"] == "matched":
            return phishtank

        # Both returned no_match → safe to call it no_match.
        if urlhaus["status"] == "no_match" and phishtank["status"] == "no_match":
            return {
                "status": "no_match",
                "provider": "URLhaus + PhishTank",
                "threat_types": [],
                "message": (
                    "Neither URLhaus nor PhishTank flagged this URL. "
                    "A no-match result is not proof of safety."
                ),
            }

        # At least one provider returned unknown.
        return {
            "status": "unknown",
            "provider": "URLhaus + PhishTank",
            "threat_types": [],
            "message": "One or more threat intelligence providers could not be reached.",
        }