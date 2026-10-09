import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlsplit

# Top brands frequently targeted by phishing campaigns
TARGET_BRANDS: Dict[str, List[str]] = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com"],
    "google": ["google.com", "accounts.google.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.co.uk"],
    "meta": ["facebook.com", "instagram.com", "whatsapp.com"],
    "netflix": ["netflix.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "metamask": ["metamask.io"],
    "chase": ["chase.com"],
    "bankofamerica": ["bankofamerica.com"],
    "wellsfargo": ["wellsfargo.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "discord": ["discord.com", "discord.gg"],
    "telegram": ["telegram.org", "t.me"],
    "linkedin": ["linkedin.com"],
    "twitter": ["twitter.com", "x.com"],
    "github": ["github.com"],
    "stripe": ["stripe.com"],
}

# TLDs with high historical abuse rates in phishing / bulk registration
HIGH_ABUSE_TLDS: Set[str] = {
    "xyz", "top", "buzz", "icu", "tk", "ml", "ga", "cf", "gq",
    "work", "click", "rest", "cam", "sbs", "monster", "fit", "surf",
    "country", "stream", "gdn", "loan", "men", "bid", "racing",
}

# Common credential harvesting keywords in paths / query params
HARVESTING_KEYWORDS: List[str] = [
    "login", "signin", "sign-in", "log-in", "auth", "authenticate",
    "credential", "verify", "verification", "checkpoint", "password",
    "passcode", "security-update", "confirm-account", "wallet-connect",
    "web3-login", "seed-phrase", "session-expired", "re-authenticate",
]


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def detect_phishing_signals(
    target_url: str,
    hostname: Optional[str] = None,
    threat_intel_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Examine URL, hostname, and path structure for phishing, typosquatting,
    deceptive subdomains, and credential-harvesting indicators.
    """
    findings: List[Dict[str, Any]] = []
    signals: List[Dict[str, Any]] = []
    total_points = 0

    if not target_url:
        return {
            "is_phishing_suspect": False,
            "phishing_score": 0,
            "signals": [],
            "findings": [],
        }

    parsed = urlsplit(target_url if "://" in target_url else f"https://{target_url}")
    host = (hostname or parsed.hostname or "").lower().rstrip(".")
    path_and_query = (parsed.path + ("?" + parsed.query if parsed.query else "")).lower()

    # 1. Threat Intel Feed Confirmation (Zero-Budget URLhaus / PhishTank)
    if threat_intel_result and threat_intel_result.get("status") == "matched":
        provider = threat_intel_result.get("provider", "Threat Intel")
        threat_types = ", ".join(threat_intel_result.get("threat_types", ["phishing/malware"]))
        total_points += 50
        signals.append({
            "type": "threat_intel_feed_match",
            "provider": provider,
            "threat_types": threat_types,
            "points": 50,
        })
        findings.append({
            "code": "FRAUD_PHISHING_CONFIRMED_FEED",
            "severity": "critical",
            "points": 50,
            "evidence": f"URL confirmed as malicious/phishing by {provider} (Threat: {threat_types}).",
            "recommendation": "Block this URL immediately. Do not visit or enter any credentials.",
        })

    # Host analysis
    parts = host.split(".") if host else []
    tld = parts[-1] if len(parts) > 1 else ""
    apex_domain = ".".join(parts[-2:]) if len(parts) >= 2 else host
    domain_label = parts[-2] if len(parts) >= 2 else host

    # 2. High-Abuse TLD Flag
    if tld in HIGH_ABUSE_TLDS:
        total_points += 15
        signals.append({
            "type": "high_abuse_tld",
            "tld": tld,
            "points": 15,
        })
        findings.append({
            "code": "FRAUD_PHISHING_HIGH_ABUSE_TLD",
            "severity": "medium",
            "points": 15,
            "evidence": f"Domain uses .{tld}, a top-level domain heavily correlated with disposable phishing campaigns.",
            "recommendation": "Scrutinize the organization identity thoroughly.",
        })

    # 3. Brand Typosquatting & Impersonation in Domain
    matched_brand = None
    is_legitimate_brand_domain = False

    for brand, leg_domains in TARGET_BRANDS.items():
        # Check if it actually IS the legitimate domain
        for leg_d in leg_domains:
            if host == leg_d or host.endswith("." + leg_d):
                is_legitimate_brand_domain = True
                break
        if is_legitimate_brand_domain:
            break

        # Check for brand token embedded inside illegitimate domain
        # e.g., paypal-update.com, microsoft-security.xyz
        if brand in host:
            matched_brand = brand
            total_points += 35
            signals.append({
                "type": "brand_in_domain",
                "brand": brand,
                "host": host,
                "points": 35,
            })
            findings.append({
                "code": "FRAUD_PHISHING_BRAND_IN_DOMAIN",
                "severity": "high",
                "points": 35,
                "evidence": f"The domain '{host}' contains the brand name '{brand}' but is NOT an authorized {brand} domain.",
                "recommendation": f"This is an unauthorized domain impersonating {brand}. Do not input credentials.",
            })
            break

        # Check for lookalike / edit distance typo (e.g., paypa1, micros0ft, tw1tter)
        # Substitute common leetspeak characters
        normalized_label = (
            domain_label.replace("0", "o")
            .replace("1", "l")
            .replace("3", "e")
            .replace("5", "s")
            .replace("@", "a")
        )
        dist = levenshtein_distance(normalized_label, brand)
        if 0 < dist <= 2 and len(brand) >= 4 and abs(len(domain_label) - len(brand)) <= 2:
            matched_brand = brand
            total_points += 30
            signals.append({
                "type": "typosquatting_lookalike",
                "brand": brand,
                "label": domain_label,
                "distance": dist,
                "points": 30,
            })
            findings.append({
                "code": "FRAUD_PHISHING_TYPOSQUATTING",
                "severity": "high",
                "points": 30,
                "evidence": f"Domain label '{domain_label}' is a visual lookalike/typosquat of target brand '{brand}' (edit distance: {dist}).",
                "recommendation": f"Suspected typosquatting of {brand}. Check the official spelling carefully.",
            })
            break

    # 4. Deceptive Subdomain Stacking
    # e.g., paypal.com.user-verification.info or login.google.com.attacker.com
    if not is_legitimate_brand_domain and len(parts) >= 3:
        subdomains = parts[:-2]
        for sub in subdomains:
            for brand, leg_domains in TARGET_BRANDS.items():
                if brand in sub:
                    total_points += 35
                    signals.append({
                        "type": "deceptive_subdomain",
                        "brand": brand,
                        "subdomain": sub,
                        "points": 35,
                    })
                    findings.append({
                        "code": "FRAUD_PHISHING_DECEPTIVE_SUBDOMAIN",
                        "severity": "high",
                        "points": 35,
                        "evidence": f"Subdomain '{sub}' mimics brand '{brand}' while registered under apex domain '{apex_domain}'.",
                        "recommendation": "The host name is structured to deceive users on mobile devices or truncated URL bars.",
                    })
                    break

    # 5. Credential Harvesting Keywords in Path / Query
    matched_harvesting = [kw for kw in HARVESTING_KEYWORDS if kw in path_and_query]
    if matched_harvesting and not is_legitimate_brand_domain:
        total_points += 20
        signals.append({
            "type": "credential_harvesting_path",
            "keywords": matched_harvesting[:3],
            "points": 20,
        })
        findings.append({
            "code": "FRAUD_PHISHING_CREDENTIAL_PATH",
            "severity": "medium",
            "points": 20,
            "evidence": f"URL path/query includes credential-harvesting triggers: {', '.join(repr(k) for k in matched_harvesting[:3])}.",
            "recommendation": "Do not enter login credentials, passwords, or authentication tokens into this form.",
        })

    # 6. Raw IP Hostname
    if host and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
        total_points += 25
        signals.append({
            "type": "raw_ip_host",
            "host": host,
            "points": 25,
        })
        findings.append({
            "code": "FRAUD_PHISHING_RAW_IP",
            "severity": "high",
            "points": 25,
            "evidence": f"URL uses raw IPv4 address ({host}) instead of an authenticated domain name.",
            "recommendation": "Legitimate enterprise services do not direct customers to raw IP addresses.",
        })

    capped_score = min(100, total_points)
    is_phishing_suspect = capped_score >= 35

    return {
        "is_phishing_suspect": is_phishing_suspect,
        "phishing_score": capped_score,
        "matched_brand": matched_brand,
        "signals": signals,
        "findings": findings,
    }
