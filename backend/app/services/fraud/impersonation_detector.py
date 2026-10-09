import re
from typing import Any, Dict, List, Optional
from app.services.fraud.phishing_detector import levenshtein_distance

# VIPs, public figures, and high-value tech/crypto accounts frequently targeted
HIGH_PROFILE_TARGETS: Dict[str, str] = {
    "elonmusk": "Elon Musk",
    "vitalikbuterin": "Vitalik Buterin",
    "cz_binance": "Changpeng Zhao (CZ)",
    "brian_armstrong": "Brian Armstrong",
    "sundarpichai": "Sundar Pichai",
    "tim_cook": "Tim Cook",
    "satyanadella": "Satya Nadella",
    "sama": "Sam Altman",
    "binance": "Binance Official",
    "coinbase": "Coinbase Official",
    "metamask": "MetaMask Official",
    "opensea": "OpenSea Official",
    "ethereum": "Ethereum Foundation",
    "support": "Customer Support",
    "helpdesk": "Help Desk",
}

# Authority-claiming affixes
AUTHORITY_AFFIXES: List[str] = [
    "official", "support", "verified", "admin", "team",
    "helpdesk", "custserv", "security", "mod", "moderator",
    "real", "original", "agent", "service", "resolution",
    "desk", "recovery", "assist",
]

# Impersonation cues in bio or metadata descriptions
BIO_IMPERSONATION_PATTERNS: List[Dict[str, Any]] = [
    {
        "pattern": r"\b(?:official\s+backup|secondary\s+account|backup\s+page)\b",
        "description": "Claims to be an 'official backup' account of a brand or celebrity.",
        "points": 25,
    },
    {
        "pattern": r"\b(?:dm|send\s+message)\s+for\s+(?:support|wallet\s+fix|recovery|help)\b",
        "description": "Directs users to DM for sensitive account or wallet recovery.",
        "points": 30,
    },
    {
        "pattern": r"\b(?:giveaway|airdrop\s+promo|send\s+crypto\s+here)\b",
        "description": "Promotes unsolicited giveaway or fund transmission.",
        "points": 30,
    },
    {
        "pattern": r"\b(?:24/7\s+support|certified\s+agent|official\s+representative)\b",
        "description": "Claims to be a certified customer service agent.",
        "points": 20,
    },
    {
        "pattern": r"\b(?:send\s+proof\s+to|telegram\s+@|whatsapp\s+\+?\d{8,})\b",
        "description": "Channels users to unmonitored private chat apps.",
        "points": 20,
    },
]


def detect_impersonation_signals(
    username: str,
    bio_text: Optional[str] = None,
    homoglyphs: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Evaluate username, bio text, and homoglyphs for impersonation, VIP mimicry,
    and authority-claiming characteristics.
    """
    signals: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    total_points = 0
    matched_target = None

    clean_user = (username or "").strip().lower().lstrip("@")

    if not clean_user:
        return {
            "is_impersonation_suspect": False,
            "impersonation_score": 0,
            "signals": [],
            "findings": [],
        }

    # 1. Authority Affix Matching
    found_affixes = [aff for aff in AUTHORITY_AFFIXES if aff in clean_user]
    if found_affixes:
        total_points += 20
        signals.append({
            "type": "authority_affix",
            "affixes": found_affixes,
            "points": 20,
        })
        findings.append({
            "code": "FRAUD_IMPERSONATION_AUTHORITY_TERMS",
            "severity": "medium",
            "points": 20,
            "evidence": f"Username contains authority-claiming terms: {', '.join(repr(a) for a in found_affixes)}.",
            "recommendation": "Verify whether this account has verified credentials on the official platform.",
        })

    # 2. VIP / Brand Name Squatting & Levenshtein Proximity
    # Normalize leetspeak
    normalized_handle = (
        clean_user.replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("5", "s")
        .replace("_", "")
        .replace("-", "")
        .replace(".", "")
    )

    for target_key, target_display in HIGH_PROFILE_TARGETS.items():
        if clean_user == target_key:
            # Exact match of a high profile name without verification
            signals.append({
                "type": "high_profile_exact_handle",
                "target": target_display,
                "points": 25,
            })
            total_points += 25
            matched_target = target_display
            findings.append({
                "code": "FRAUD_IMPERSONATION_TARGET_NAME",
                "severity": "high",
                "points": 25,
                "evidence": f"Handle directly matches high-profile entity '{target_display}'.",
                "recommendation": f"Check for official verification badges before interacting with {target_display}.",
            })
            break

        # Check if handle embeds target with affixes, e.g. elonmusk_official or support_binance
        if target_key in normalized_handle:
            matched_target = target_display
            total_points += 30
            signals.append({
                "type": "high_profile_embedded",
                "target": target_display,
                "points": 30,
            })
            findings.append({
                "code": "FRAUD_IMPERSONATION_EMBEDDED_TARGET",
                "severity": "high",
                "points": 30,
                "evidence": f"Username incorporates protected brand or figure '{target_display}'.",
                "recommendation": "Watch for fake accounts impersonating well-known figures.",
            })
            break

        # Check small edit distance (e.g. el0nmusk, binancc)
        dist = levenshtein_distance(normalized_handle, target_key)
        if 0 < dist <= 2 and len(target_key) >= 5 and abs(len(normalized_handle) - len(target_key)) <= 2:
            matched_target = target_display
            total_points += 35
            signals.append({
                "type": "high_profile_typosquat",
                "target": target_display,
                "distance": dist,
                "points": 35,
            })
            findings.append({
                "code": "FRAUD_IMPERSONATION_TYPOSQUAT_VIP",
                "severity": "high",
                "points": 35,
                "evidence": f"Username '{clean_user}' is a lookalike/typosquat of '{target_display}' (edit distance: {dist}).",
                "recommendation": f"Account is almost certainly impersonating {target_display}.",
            })
            break

    # 3. Unicode Homoglyphs Substitution
    if homoglyphs and len(homoglyphs) > 0:
        total_points += 25
        signals.append({
            "type": "unicode_homoglyphs",
            "count": len(homoglyphs),
            "points": 25,
        })
        findings.append({
            "code": "FRAUD_IMPERSONATION_HOMOGLYPHS",
            "severity": "high",
            "points": 25,
            "evidence": f"Username utilizes {len(homoglyphs)} non-Latin/homoglyph character lookalikes to fool visual inspection.",
            "recommendation": "The handle uses character spoofing to mimic another entity.",
        })

    # 4. Bio & Metadata Impersonation Patterns
    if bio_text:
        bio_lower = bio_text.lower()
        for item in BIO_IMPERSONATION_PATTERNS:
            if re.search(item["pattern"], bio_lower):
                total_points += item["points"]
                signals.append({
                    "type": "bio_impersonation_cue",
                    "description": item["description"],
                    "points": item["points"],
                })
                findings.append({
                    "code": "FRAUD_IMPERSONATION_BIO_PATTERN",
                    "severity": "medium",
                    "points": item["points"],
                    "evidence": f"Bio text signal: {item['description']}",
                    "recommendation": "Do not follow instructions in bios soliciting direct messages or payment transfers.",
                })

    capped_score = min(100, total_points)
    is_impersonation_suspect = capped_score >= 35

    return {
        "is_impersonation_suspect": is_impersonation_suspect,
        "impersonation_score": capped_score,
        "matched_target": matched_target,
        "signals": signals,
        "findings": findings,
    }
