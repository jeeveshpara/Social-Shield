import math
import re
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional
import httpx

# Common Cyrillic / Greek lookalike homoglyphs mapped to ASCII
HOMOGLYPH_MAP = {
    "\u0430": "a",  # Cyrillic small a
    "\u0441": "c",  # Cyrillic small es (c)
    "\u0435": "e",  # Cyrillic small ie (e)
    "\u0456": "i",  # Cyrillic small byelorussian-ukrainian i
    "\u0458": "j",  # Cyrillic small je
    "\u043e": "o",  # Cyrillic small o
    "\u0440": "p",  # Cyrillic small er (p)
    "\u0455": "s",  # Cyrillic small dze (s)
    "\u0443": "y",  # Cyrillic small u (y)
    "\u0445": "x",  # Cyrillic small ha (x)
    "\u0410": "A",  # Cyrillic capital A
    "\u0412": "B",  # Cyrillic capital Ve (B)
    "\u0415": "E",  # Cyrillic capital Ie (E)
    "\u041a": "K",  # Cyrillic capital Ka (K)
    "\u041c": "M",  # Cyrillic capital Em (M)
    "\u041d": "H",  # Cyrillic capital En (H)
    "\u041e": "O",  # Cyrillic capital O
    "\u0420": "P",  # Cyrillic capital Er (P)
    "\u0421": "C",  # Cyrillic capital Es (C)
    "\u0422": "T",  # Cyrillic capital Te (T)
    "\u0425": "X",  # Cyrillic capital Ha (X)
    "\u03bf": "o",  # Greek small omicron
    "\u039f": "O",  # Greek capital omicron
}

IMPERSONATION_TERMS = [
    "admin",
    "administrator",
    "official",
    "support",
    "security",
    "verified",
    "helpdesk",
    "customer-care",
    "mod",
    "moderator",
    "compliance",
    "billing",
    "desk",
    "staff",
    "system",
    "service",
]

LEET_REPLACEMENTS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
    "$": "s",
}

PLATFORM_PROBES = [
    {
        "name": "GitHub",
        "url_template": "https://api.github.com/users/{username}",
        "profile_url": "https://github.com/{username}",
        "method": "GET",
        "headers": {"User-Agent": "SocialShield-OSINT-Probe/1.0", "Accept": "application/vnd.github.v3+json"},
        "success_status": [200],
        "not_found_status": [404],
    },
    {
        "name": "Reddit",
        "url_template": "https://www.reddit.com/user/{username}/about.json",
        "profile_url": "https://www.reddit.com/user/{username}",
        "method": "GET",
        "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SocialShield-OSINT/1.0"},
        "success_status": [200],
        "not_found_status": [404],
    },
    {
        "name": "GitLab",
        "url_template": "https://gitlab.com/{username}",
        "profile_url": "https://gitlab.com/{username}",
        "method": "GET",
        "headers": {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SocialShield-OSINT/1.0"},
        "success_status": [200],
        "not_found_status": [404],
    },
    {
        "name": "Gravatar",
        "url_template": "https://gravatar.com/{username}.json",
        "profile_url": "https://gravatar.com/{username}",
        "method": "GET",
        "headers": {"User-Agent": "SocialShield-OSINT/1.0"},
        "success_status": [200],
        "not_found_status": [404],
    },
    {
        "name": "Dev.to",
        "url_template": "https://dev.to/api/users/by_username?url={username}",
        "profile_url": "https://dev.to/{username}",
        "method": "GET",
        "headers": {"User-Agent": "SocialShield-OSINT/1.0"},
        "success_status": [200],
        "not_found_status": [404],
    },
    {
        "name": "HackerNews",
        "url_template": "https://hacker-news.firebaseio.com/v0/user/{username}.json",
        "profile_url": "https://news.ycombinator.com/user?id={username}",
        "method": "GET",
        "headers": {"User-Agent": "SocialShield-OSINT/1.0"},
        "success_status": [200],
        "not_found_status": [404],
        "check_json_null": True,
    },
]


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy for a given string."""
    if not text:
        return 0.0
    frequencies: Dict[str, int] = {}
    for char in text:
        frequencies[char] = frequencies.get(char, 0) + 1
    total = len(text)
    entropy = -sum((count / total) * math.log2(count / total) for count in frequencies.values())
    return round(entropy, 2)


def detect_homoglyphs(text: str) -> List[Dict[str, str]]:
    """Detect non-ASCII characters that visually mimic Latin characters."""
    detected = []
    for idx, char in enumerate(text):
        if char in HOMOGLYPH_MAP:
            detected.append({
                "char": char,
                "position": idx,
                "mimics": HOMOGLYPH_MAP[char],
                "unicode_name": unicodedata.name(char, "UNKNOWN"),
            })
    return detected


def normalize_leetspeak(text: str) -> str:
    """Normalize common leetspeak substitutions to standard characters."""
    result = []
    for char in text.lower():
        result.append(LEET_REPLACEMENTS.get(char, char))
    return "".join(result)


def check_impersonation_keywords(username: str) -> List[str]:
    """Check for suspicious authority terms in username or leet-normalized username."""
    lowered = username.lower()
    normalized = normalize_leetspeak(username)
    matches = set()
    for term in IMPERSONATION_TERMS:
        if term in lowered or term in normalized:
            matches.add(term)
    return sorted(list(matches))


def _probe_single_platform(platform: Dict[str, Any], username: str) -> Dict[str, Any]:
    url = platform["url_template"].format(username=username)
    profile_url = platform["profile_url"].format(username=username)
    headers = platform.get("headers", {})

    try:
        with httpx.Client(timeout=2.8, follow_redirects=True) as client:
            resp = client.request(platform["method"], url, headers=headers)
            status_code = resp.status_code

            if status_code in platform.get("success_status", [200]):
                if platform.get("check_json_null"):
                    try:
                        if resp.json() is None:
                            return {"platform": platform["name"], "status": "not_found", "profile_url": profile_url}
                    except Exception:
                        pass
                return {
                    "platform": platform["name"],
                    "status": "found",
                    "profile_url": profile_url,
                    "status_code": status_code,
                }
            elif status_code in platform.get("not_found_status", [404]):
                return {"platform": platform["name"], "status": "not_found", "profile_url": profile_url}
            elif status_code == 429:
                return {"platform": platform["name"], "status": "rate_limited", "profile_url": profile_url}
            else:
                return {"platform": platform["name"], "status": "unknown", "profile_url": profile_url}
    except (httpx.TimeoutException, httpx.RequestError):
        return {"platform": platform["name"], "status": "timeout", "profile_url": profile_url}
    except Exception:
        return {"platform": platform["name"], "status": "error", "profile_url": profile_url}


def probe_username_footprint(username: str, max_workers: int = 4) -> List[Dict[str, Any]]:
    """Check for public presence across zero-budget platform endpoints concurrently."""
    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_probe_single_platform, p, username): p["name"] for p in PLATFORM_PROBES}
        for future in as_completed(futures):
            try:
                res = future.result()
                results.append(res)
            except Exception:
                platform_name = futures[future]
                results.append({"platform": platform_name, "status": "error"})
    # Sort deterministically by platform name
    results.sort(key=lambda x: x["platform"])
    return results


def analyze_username(username: str, run_probes: bool = True) -> Dict[str, Any]:
    """
    Perform deep OSINT analysis on a username.
    Returns structured analysis, indicators, findings, and evidence artifacts.
    """
    findings = []
    clean_username = username.strip().removeprefix("@")

    entropy = calculate_entropy(clean_username)
    homoglyphs = detect_homoglyphs(clean_username)
    impersonation_terms = check_impersonation_keywords(clean_username)
    has_long_digits = bool(re.search(r"\d{5,}", clean_username))
    has_hex_hash = bool(re.fullmatch(r"[a-f0-9]{16,64}", clean_username, re.IGNORECASE))

    # Finding: Homoglyphs
    if homoglyphs:
        findings.append({
            "code": "OSINT_USERNAME_HOMOGLYPH_SPOOFING",
            "severity": "high",
            "points": 35,
            "evidence": (
                f"Detected {len(homoglyphs)} non-ASCII homoglyph character(s) mimicking Latin script: "
                + ", ".join(f"'{h['char']}' (mimics '{h['mimics']}', {h['unicode_name']})" for h in homoglyphs)
            ),
            "recommendation": (
                "Treat this account with high suspicion. Homoglyphs are frequently used in visual spoofing and impersonation attacks."
            ),
        })

    # Finding: Impersonation / Authority Claiming
    if impersonation_terms:
        findings.append({
            "code": "OSINT_USERNAME_IMPERSONATION_SIGNAL",
            "severity": "medium",
            "points": 20,
            "evidence": f"Username contains authority-claiming keyword(s): {', '.join(impersonation_terms)}.",
            "recommendation": "Cross-reference with the target organization's verified roster or security portal.",
        })

    # Finding: High Entropy / Algorithmic Generator
    if len(clean_username) >= 10 and entropy >= 3.6:
        findings.append({
            "code": "OSINT_USERNAME_HIGH_ENTROPY",
            "severity": "medium",
            "points": 15,
            "evidence": f"Username exhibits high Shannon entropy ({entropy} bits/char), typical of DGA or automated bot generation.",
            "recommendation": "Check account history and cross-platform footprint to confirm human ownership.",
        })
    elif has_hex_hash:
        findings.append({
            "code": "OSINT_USERNAME_HEX_HASH_PATTERN",
            "severity": "low",
            "points": 10,
            "evidence": "Username resembles an automated hex hash or machine identifier.",
            "recommendation": "Verify whether this account was created by an automated campaign.",
        })

    if has_long_digits:
        findings.append({
            "code": "OSINT_USERNAME_LONG_DIGIT_SEQUENCE",
            "severity": "info",
            "points": 5,
            "evidence": "Username contains 5 or more consecutive digits, commonly seen in auto-generated fallback handles.",
            "recommendation": "Evaluate account activity alongside profile metadata.",
        })

    # Cross-platform footprint probe
    footprint = []
    if run_probes:
        footprint = probe_username_footprint(clean_username)
        found_platforms = [p["platform"] for p in footprint if p.get("status") == "found"]

        if found_platforms:
            findings.append({
                "code": "OSINT_FOOTPRINT_ESTABLISHED",
                "severity": "info",
                "points": 0,
                "evidence": f"Matching public username found on {len(found_platforms)} platform(s): {', '.join(found_platforms)}.",
                "recommendation": "Review the linked public profiles for consistency in biography and activity timelines.",
            })
        else:
            findings.append({
                "code": "OSINT_FOOTPRINT_ISOLATED",
                "severity": "low",
                "points": 5,
                "evidence": "No matching public profiles were found across the surveyed public developer and community platforms.",
                "recommendation": "Single-platform or unestablished accounts require greater verification before trust is granted.",
            })

    return {
        "username": clean_username,
        "entropy": entropy,
        "homoglyphs": homoglyphs,
        "impersonation_terms": impersonation_terms,
        "footprint": footprint,
        "findings": findings,
    }
