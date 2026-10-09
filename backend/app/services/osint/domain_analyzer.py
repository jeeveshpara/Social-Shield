from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import httpx


CLOUDFLARE_DOH_URL = "https://cloudflare-dns.com/dns-query"
GOOGLE_DOH_URL = "https://dns.google/resolve"
RDAP_BASE_URL = "https://rdap.org/domain/"

# Known high-abuse or disposable TLDs frequently abused in rapid phishing campaigns
HIGH_ABUSE_TLDS = {
    "top", "xyz", "buzz", "fit", "icu", "wang", "monster", "work", "cam",
    "tk", "ml", "ga", "cf", "gq", "click", "rest", "surf", "live", "link",
}


def query_doh(domain: str, record_type: str = "A") -> List[str]:
    """
    Query DNS records using zero-budget public DNS-over-HTTPS (DoH).
    Primary: Cloudflare DoH; Fallback: Google DoH.
    """
    headers = {"Accept": "application/dns-json", "User-Agent": "SocialShield-OSINT/1.0"}
    params = {"name": domain, "type": record_type}

    # Try Cloudflare DoH first
    try:
        with httpx.Client(timeout=2.8) as client:
            resp = client.get(CLOUDFLARE_DOH_URL, params=params, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get("Answer", [])
                return [ans.get("data", "").strip('"') for ans in answers if "data" in ans]
    except Exception:
        pass

    # Fallback to Google Public DNS DoH
    try:
        with httpx.Client(timeout=2.8) as client:
            resp = client.get(GOOGLE_DOH_URL, params=params, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                answers = data.get("Answer", [])
                return [ans.get("data", "").strip('"') for ans in answers if "data" in ans]
    except Exception:
        pass

    return []


def query_rdap(domain: str) -> Dict[str, Any]:
    """
    Query domain registration information via open ICANN RDAP (zero-cost open standard).
    """
    url = f"{RDAP_BASE_URL}{domain}"
    headers = {"Accept": "application/rdap+json, application/json", "User-Agent": "SocialShield-OSINT/1.0"}

    try:
        with httpx.Client(timeout=3.5, follow_redirects=True) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code != 200:
                return {"status": "unavailable", "message": f"RDAP query returned status {resp.status_code}"}

            data = resp.json()

            registration_date: Optional[str] = None
            expiration_date: Optional[str] = None
            last_changed_date: Optional[str] = None

            for event in data.get("events", []):
                action = event.get("eventAction", "").lower()
                date_str = event.get("eventDate")
                if action == "registration" and date_str:
                    registration_date = date_str
                elif action == "expiration" and date_str:
                    expiration_date = date_str
                elif action in {"last changed", "last update"} and date_str:
                    last_changed_date = date_str

            # Parse registrar name
            registrar = "Unknown"
            for entity in data.get("entities", []):
                roles = entity.get("roles", [])
                if "registrar" in roles:
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1 and isinstance(vcard[1], list):
                        for item in vcard[1]:
                            if isinstance(item, list) and len(item) > 3 and item[0] == "fn":
                                registrar = item[3]
                                break
                    if registrar == "Unknown" and entity.get("handle"):
                        registrar = entity.get("handle")

            age_days: Optional[int] = None
            if registration_date:
                try:
                    # Parse ISO format e.g. 2024-01-15T12:00:00Z
                    clean_date = registration_date.replace("Z", "+00:00")
                    reg_dt = datetime.fromisoformat(clean_date)
                    now_utc = datetime.now(timezone.utc)
                    age_days = max(0, (now_utc - reg_dt).days)
                except Exception:
                    pass

            return {
                "status": "success",
                "domain": domain,
                "registrar": registrar,
                "registration_date": registration_date,
                "expiration_date": expiration_date,
                "last_changed_date": last_changed_date,
                "age_days": age_days,
            }

    except httpx.TimeoutException:
        return {"status": "timeout", "message": "RDAP registry lookup timed out."}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def analyze_domain(host: str) -> Dict[str, Any]:
    """
    Perform comprehensive OSINT domain intelligence:
    - DNS A/AAAA, MX, NS, TXT (SPF & DMARC)
    - RDAP domain age & registrar
    - TLD risk profiling
    """
    clean_host = host.lower().rstrip(".")
    labels = clean_host.split(".")
    tld = labels[-1] if len(labels) > 1 else ""

    # Determine apex / registrable domain (heuristic fallback if no tldextract)
    if len(labels) >= 2:
        apex_domain = ".".join(labels[-2:])
    else:
        apex_domain = clean_host

    findings = []
    dns_intel: Dict[str, Any] = {}

    # 1. DNS Resolution
    a_records = query_doh(clean_host, "A")
    aaaa_records = query_doh(clean_host, "AAAA")
    mx_records = query_doh(apex_domain, "MX")
    ns_records = query_doh(apex_domain, "NS")
    txt_records = query_doh(apex_domain, "TXT")
    dmarc_records = query_doh(f"_dmarc.{apex_domain}", "TXT")

    dns_intel = {
        "a_records": a_records,
        "aaaa_records": aaaa_records,
        "mx_records": mx_records,
        "ns_records": ns_records,
        "spf_records": [r for r in txt_records if "v=spf1" in r.lower()],
        "dmarc_records": [r for r in dmarc_records if "v=dmarc1" in r.lower()],
    }

    if not a_records and not aaaa_records:
        findings.append({
            "code": "OSINT_DNS_NO_RESOLVING_IP",
            "severity": "medium",
            "points": 20,
            "evidence": f"Domain {clean_host} does not resolve to any active A or AAAA IP records.",
            "recommendation": "The host may be inactive, parked, or used solely for non-web infrastructure.",
        })
    else:
        findings.append({
            "code": "OSINT_DNS_RESOLVED",
            "severity": "info",
            "points": 0,
            "evidence": f"Domain resolves to {len(a_records)} IPv4 address(es) [{', '.join(a_records[:3])}].",
            "recommendation": "Review IP geolocation and hosting provider autonomous system (ASN).",
        })

    # SPF / DMARC check (Anti-spoofing posture)
    has_spf = bool(dns_intel["spf_records"])
    has_dmarc = bool(dns_intel["dmarc_records"])
    if not has_spf and not has_dmarc:
        findings.append({
            "code": "OSINT_DOMAIN_NO_EMAIL_SECURITY",
            "severity": "low",
            "points": 10,
            "evidence": f"Domain {apex_domain} lacks both SPF and DMARC TXT records.",
            "recommendation": "Emails claiming to originate from this domain could be easily spoofed.",
        })

    # 2. TLD Risk Profiling
    if tld in HIGH_ABUSE_TLDS:
        findings.append({
            "code": "OSINT_DOMAIN_HIGH_ABUSE_TLD",
            "severity": "medium",
            "points": 25,
            "evidence": f"Top-level domain (.{tld}) is categorized as high-abuse / high-fraud frequency.",
            "recommendation": "Exercise heightened caution. Verify brand identity independently.",
        })

    # Subdomain depth
    if len(labels) >= 5:
        findings.append({
            "code": "OSINT_DOMAIN_DEEP_SUBDOMAINS",
            "severity": "low",
            "points": 10,
            "evidence": f"Hostname contains {len(labels)} subdomain levels, often used to conceal true domain identity.",
            "recommendation": "Inspect the root registrable domain rather than the leftmost prefix.",
        })

    # Punycode / IDN
    if "xn--" in clean_host:
        findings.append({
            "code": "OSINT_DOMAIN_PUNYCODE_IDN",
            "severity": "high",
            "points": 30,
            "evidence": f"Hostname uses Punycode encoding ({clean_host}), a common indicator of internationalized domain lookalike attacks.",
            "recommendation": "Inspect character-by-character against authentic brand domains.",
        })

    # 3. RDAP Registration Intelligence
    rdap_info = query_rdap(apex_domain)
    if rdap_info.get("status") == "success":
        age_days = rdap_info.get("age_days")
        registrar = rdap_info.get("registrar", "Unknown")

        if age_days is not None:
            if age_days < 14:
                findings.append({
                    "code": "OSINT_DOMAIN_NEWLY_REGISTERED_CRITICAL",
                    "severity": "high",
                    "points": 40,
                    "evidence": f"Domain was registered only {age_days} days ago (Registration: {rdap_info['registration_date']}). Brand new domains are high-confidence indicators of malicious campaigns.",
                    "recommendation": "Do not trust brand claims or submit payment details to newly registered domains.",
                })
            elif age_days < 60:
                findings.append({
                    "code": "OSINT_DOMAIN_NEWLY_REGISTERED_ELEVATED",
                    "severity": "medium",
                    "points": 20,
                    "evidence": f"Domain was registered recently ({age_days} days ago).",
                    "recommendation": "Verify whether this domain corresponds to an officially announced service launch.",
                })
            elif age_days > 730:
                findings.append({
                    "code": "OSINT_DOMAIN_ESTABLISHED_AGE",
                    "severity": "info",
                    "points": 0,
                    "evidence": f"Domain has an established registration history ({age_days} days old, registered {rdap_info['registration_date']}).",
                    "recommendation": "Established age lowers the likelihood of throwaway phishing infrastructure.",
                })

    return {
        "hostname": clean_host,
        "apex_domain": apex_domain,
        "tld": tld,
        "dns": dns_intel,
        "rdap": rdap_info,
        "findings": findings,
    }
