import ipaddress
import re
from urllib.parse import unquote, urlsplit
from typing import Any, Dict, List, Optional
import httpx
from app.services.threat_intel import lookup_url


SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "goo.gl",
    "cutt.ly", "rebrand.ly", "rb.gy", "shorturl.at", "t.me", "wa.me", "linktr.ee",
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".apk", ".vbs", ".iso", ".zip", ".msi",
    ".ps1", ".cmd", ".jar", ".dmg", ".tar.gz", ".hta", ".wsf",
}

PHISHING_KEYWORDS = {
    "verify": 12,
    "login": 8,
    "signin": 8,
    "password": 15,
    "wallet": 12,
    "metamask": 20,
    "airdrop": 15,
    "giveaway": 12,
    "claim": 10,
    "account-suspended": 18,
    "security-alert": 15,
    "banking": 12,
    "update-billing": 15,
    "re-activate": 12,
    "urgent": 8,
}


def trace_redirects(start_url: str, max_hops: int = 5) -> Dict[str, Any]:
    """
    Safely follow HTTP redirects to unshorten URLs and expose destination cloaking.
    """
    chain = []
    current_url = start_url
    client_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SocialShield-OSINT/1.0",
        "Accept": "*/*",
    }

    try:
        with httpx.Client(timeout=3.0, follow_redirects=False) as client:
            for hop in range(max_hops):
                try:
                    resp = client.head(current_url, headers=client_headers)
                except (httpx.RequestError, httpx.HTTPStatusError):
                    # Fallback to GET stream if HEAD is blocked by server
                    resp = client.get(current_url, headers=client_headers)

                status_code = resp.status_code
                chain.append({
                    "hop": hop + 1,
                    "url": current_url,
                    "status_code": status_code,
                })

                if 300 <= status_code < 400 and "location" in resp.headers:
                    next_url = resp.headers["location"]
                    if next_url.startswith("/"):
                        parsed_cur = urlsplit(current_url)
                        next_url = f"{parsed_cur.scheme}://{parsed_cur.netloc}{next_url}"
                    current_url = next_url
                else:
                    break

        return {
            "initial_url": start_url,
            "final_url": current_url,
            "hops_count": len(chain),
            "redirect_chain": chain,
            "has_redirects": len(chain) > 1,
        }
    except Exception as exc:
        return {
            "initial_url": start_url,
            "final_url": current_url,
            "hops_count": len(chain),
            "redirect_chain": chain,
            "has_redirects": len(chain) > 1,
            "error": str(exc),
        }


def analyze_url(url: str, trace_chain: bool = True) -> Dict[str, Any]:
    """
    Perform deep OSINT URL analysis:
    - Redirection trace & unshortening
    - Dangerous payloads and extension detection
    - Obfuscation and phishing heuristics
    - Zero-budget threat intelligence feeds (URLhaus + PhishTank)
    """
    findings = []
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    clean_host = host.lower()
    full_path_query = (parsed.path + "?" + parsed.query).lower()

    # Redirection tracing
    is_shortener = clean_host in SHORTENER_DOMAINS
    trace_info = trace_redirects(url) if trace_chain else {
        "initial_url": url,
        "final_url": url,
        "hops_count": 1,
        "redirect_chain": [{"hop": 1, "url": url, "status_code": 200}],
        "has_redirects": False,
    }

    final_url = trace_info.get("final_url", url)

    if is_shortener:
        findings.append({
            "code": "OSINT_URL_SHORTENER_DETECTED",
            "severity": "medium",
            "points": 15,
            "evidence": f"URL uses a known link shortener ({clean_host}) that masks the real destination: {final_url}.",
            "recommendation": "Inspect the final unshortened URL destination before navigating.",
        })

    if trace_info.get("hops_count", 0) > 2:
        findings.append({
            "code": "OSINT_URL_MULTIPLE_REDIRECTS",
            "severity": "medium",
            "points": 15,
            "evidence": f"URL traversed {trace_info['hops_count']} redirect hops to reach {final_url}.",
            "recommendation": "Multi-hop chains are frequently used in traffic distribution systems (TDS) and phishing lures.",
        })

    # Scheme
    if parsed.scheme.lower() != "https":
        findings.append({
            "code": "OSINT_URL_NO_HTTPS",
            "severity": "medium",
            "points": 15,
            "evidence": "URL transmits data via unencrypted HTTP rather than HTTPS.",
            "recommendation": "Do not submit login credentials, sensitive data, or financial information.",
        })

    # IP Host check
    is_ip = False
    try:
        ipaddress.ip_address(clean_host.strip("[]"))
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        findings.append({
            "code": "OSINT_URL_IP_HOST",
            "severity": "high",
            "points": 25,
            "evidence": f"URL uses a direct numerical IP address ({clean_host}) instead of a registered domain name.",
            "recommendation": "Direct IP destinations bypass domain reputation filters and are high-risk indicators.",
        })

    # Dangerous payload extensions
    path_decoded = unquote(parsed.path).lower()
    matched_exts = [ext for ext in DANGEROUS_EXTENSIONS if path_decoded.endswith(ext)]
    if matched_exts:
        findings.append({
            "code": "OSINT_URL_EXECUTABLE_PAYLOAD",
            "severity": "high",
            "points": 35,
            "evidence": f"URL links directly to a potentially malicious executable or archive payload ({', '.join(matched_exts)}).",
            "recommendation": "Do not download or execute files from this link.",
        })

    # Suspicious Phishing Keywords
    matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in full_path_query]
    if matched_keywords:
        points = min(25, sum(PHISHING_KEYWORDS[kw] for kw in matched_keywords))
        findings.append({
            "code": "OSINT_URL_PHISHING_KEYWORDS",
            "severity": "medium",
            "points": points,
            "evidence": f"URL path/query contains credential-harvesting or scam triggers: {', '.join(matched_keywords)}.",
            "recommendation": "Verify whether this is an authentic corporate portal or an impersonation replica.",
        })

    # Check Zero-Budget Threat Feeds (URLhaus + PhishTank)
    # Check original URL and final unshortened URL
    urls_to_check = [url]
    if final_url != url:
        urls_to_check.append(final_url)

    reputation_result = None
    for u in urls_to_check:
        rep = lookup_url(u)
        if rep.get("status") == "matched":
            reputation_result = rep
            break
        elif reputation_result is None:
            reputation_result = rep

    if reputation_result:
        if reputation_result.get("status") == "matched":
            threat_types = reputation_result.get("threat_types", [])
            findings.append({
                "code": "OSINT_THREAT_INTEL_MATCH",
                "severity": "high",
                "points": 50,
                "evidence": (
                    f"Flagged by {reputation_result.get('provider')} public threat feed. "
                    f"Threat: {', '.join(threat_types) or 'Malicious'}."
                ),
                "recommendation": "Block and report this link immediately across corporate or personal channels.",
            })
        elif reputation_result.get("status") == "no_match":
            findings.append({
                "code": "OSINT_THREAT_INTEL_CLEAN",
                "severity": "info",
                "points": 0,
                "evidence": reputation_result.get("message", "No records found in public feeds."),
                "recommendation": "Zero hits on public threat lists does not guarantee safety. Contextual analysis remains necessary.",
            })

    return {
        "url": url,
        "final_url": final_url,
        "host": clean_host,
        "is_shortener": is_shortener,
        "trace": trace_info,
        "reputation": reputation_result,
        "findings": findings,
    }
