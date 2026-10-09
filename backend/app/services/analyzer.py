
import ipaddress
import re
from urllib.parse import urlsplit, unquote

PLATFORM_DOMAINS = {
    "instagram": ["instagram.com"],
    "facebook": ["facebook.com", "fb.com"],
    "linkedin": ["linkedin.com"],
    "x": ["x.com", "twitter.com"],
    "github": ["github.com"],
    "youtube": ["youtube.com", "youtu.be"],
    "tiktok": ["tiktok.com"],
}

SUSPICIOUS_TERMS = {
    "verify": 10,
    "login": 5,
    "password": 10,
    "wallet": 8,
    "airdrop": 10,
    "giveaway": 8,
    "claim-prize": 12,
    "account-suspended": 12,
    "urgent": 5,
}

IMPERSONATION_TERMS = {
    "official", "support", "verified", "admin",
    "security", "helpdesk", "customer-care"
}


def add_finding(findings, code, severity, points, evidence, recommendation):
    findings.append({
        "code": code,
        "severity": severity,
        "points": points,
        "evidence": evidence,
        "recommendation": recommendation,
    })


def classify_risk(score):
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 15:
        return "LOW"
    return "INFO"


def get_platform(host):
    host = (host or "").lower().rstrip(".")
    for platform, domains in PLATFORM_DOMAINS.items():
        for domain in domains:
            if host == domain or host.endswith("." + domain):
                return platform
    return "unknown"


def normalize_input(value):
    value = value.strip()

    if not value:
        raise ValueError("Enter a username or profile URL.")

    if len(value) > 2048:
        raise ValueError("Input is too long.")

    if any(ord(char) < 32 for char in value):
        raise ValueError("Input contains invalid control characters.")

    # A bare domain or URL is treated as a URL.
    if "://" in value or (
        "." in value and "/" in value and " " not in value
    ):
        candidate = value if "://" in value else "https://" + value
        parsed = urlsplit(candidate)

        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS URLs are supported.")

        if not parsed.hostname:
            raise ValueError("The supplied URL has no valid hostname.")

        try:
            _ = parsed.port
        except ValueError:
            raise ValueError("The URL contains an invalid port.")

        if parsed.username or parsed.password:
            raise ValueError(
                "URLs containing embedded credentials are not accepted."
            )

        host = parsed.hostname.encode("idna").decode("ascii").lower()

        normalized = parsed._replace(
            scheme=parsed.scheme.lower(),
            netloc=host + (f":{parsed.port}" if parsed.port else "")
        ).geturl()

        return {
            "input_type": "url",
            "normalized": normalized,
            "host": host,
            "platform": get_platform(host),
        }

    username = value.removeprefix("@")

    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", username):
        raise ValueError(
            "Enter a valid username or a full HTTP/HTTPS profile URL."
        )

    return {
        "input_type": "username",
        "normalized": username,
        "host": None,
        "platform": "unknown",
    }


def analyze_input(value):
    item = normalize_input(value)
    findings = []
    normalized = item["normalized"]

    if item["input_type"] == "url":
        parsed = urlsplit(normalized)
        host = item["host"]
        hostname_ascii = host.lower()
        decoded_path = unquote(parsed.path).lower()
        full_text = (parsed.path + "?" + parsed.query).lower()

        if parsed.scheme.lower() != "https":
            add_finding(
                findings, "URL_NO_HTTPS", "medium", 15,
                "The URL uses HTTP rather than HTTPS.",
                "Verify the destination independently before sharing information."
            )

        try:
            ipaddress.ip_address(host.strip("[]"))
            is_ip_address = True
        except ValueError:
            is_ip_address = False

        if is_ip_address:
            add_finding(
                findings, "URL_IP_HOST", "high", 20,
                "The URL uses an IP address as its hostname.",
                "Confirm the destination through a trusted official source."
            )

        if "xn--" in hostname_ascii:
            add_finding(
                findings, "URL_PUNYCODE", "medium", 15,
                "The hostname contains an internationalized domain label.",
                "Inspect the domain carefully for lookalike characters."
            )

        if len(host.split(".")) >= 5:
            add_finding(
                findings, "URL_DEEP_SUBDOMAINS", "low", 10,
                "The hostname has many subdomain levels.",
                "Check the registrable domain, not just the leftmost hostname."
            )

        if len(normalized) > 200:
            add_finding(
                findings, "URL_LONG", "low", 5,
                "The URL is unusually long.",
                "Inspect its destination and parameters before opening it."
            )

        matched_terms = [
            term for term in SUSPICIOUS_TERMS
            if term in full_text
        ]

        if matched_terms:
            points = min(
                20,
                sum(SUSPICIOUS_TERMS[t] for t in matched_terms)
            )
            add_finding(
                findings, "URL_SUSPICIOUS_TERMS", "medium", points,
                "Suspicious terms found in the URL: "
                + ", ".join(matched_terms),
                "Check the request through the organization's official website."
            )

        if not findings:
            add_finding(
                findings, "URL_NO_LOCAL_FLAGS", "info", 0,
                "No configured URL-pattern indicators were detected.",
                "This is not proof that the URL is safe; reputation checks are not configured."
            )

    else:
        username = normalized
        lowered = username.lower()

        matched_terms = sorted(
            term for term in IMPERSONATION_TERMS
            if term in lowered
        )

        if matched_terms:
            add_finding(
                findings, "USERNAME_IMPERSONATION_TERMS", "low", 10,
                "Username contains potentially authority-claiming terms: "
                + ", ".join(matched_terms),
                "Compare the account with the person's or organization's official profile."
            )

        if re.search(r"\d{5,}", username):
            add_finding(
                findings, "USERNAME_LONG_DIGIT_SEQUENCE", "info", 5,
                "Username contains a long sequence of digits.",
                "Treat this as a weak indicator only; many legitimate usernames contain digits."
            )

        if not findings:
            add_finding(
                findings, "USERNAME_NO_LOCAL_FLAGS", "info", 0,
                "No configured username-pattern indicators were detected.",
                "The account's existence, ownership, and reputation have not been verified."
            )

    # Explainable, capped scoring: each finding contributes its declared points.
    score = min(100, sum(f["points"] for f in findings))

    return {
        "target": normalized,
        "input_type": item["input_type"],
        "platform": item["platform"],
        "risk_score": score,
        "risk_level": classify_risk(score),
        "findings": findings,
        "analysis_scope": (
            "Local heuristic analysis only. No account was logged into, "
            "no private data was accessed, and no external URL was fetched."
        ),
    }