import re
from typing import Any, Dict, List

SCAM_CATEGORIES: Dict[str, Dict[str, Any]] = {
    "crypto_giveaway": {
        "title": "Cryptocurrency Giveaway & Doubler Fraud",
        "severity": "high",
        "points": 35,
        "patterns": [
            r"\b(?:send|deposit)\s+\d+(?:\.\d+)?\s*(?:eth|btc|sol|usdt|bnb|xrp)\b",
            r"\b(?:double|2x|3x|multiply)\s+your\s+(?:crypto|btc|eth|sol|money|investment)\b",
            r"\b(?:claim|free)\s+airdrop\b",
            r"\b(?:connect|sync|validate)\s+(?:wallet|metamask|phantom|trustwallet|keplr)\b",
            r"\b(?:seed|recovery|secret)\s+phrase\b",
            r"\b(?:claim|mint)\s+(?:tokens?|nft|airdrop)\s+now\b",
            r"\bguaranteed\s+(?:daily|weekly|monthly)\s+returns?\b",
            r"\btrading\s+bot\s+100%\s+profit\b",
        ],
        "recommendation": "Never send crypto with expectations of receiving a multiplier. Legitimate projects never solicit private seed phrases or wallet drain approvals.",
    },
    "advance_fee_lottery": {
        "title": "Advance-Fee & Lottery / Prize Fraud",
        "severity": "high",
        "points": 30,
        "patterns": [
            r"\bcongratulations.*(?:won|selected|winner|chosen)\b",
            r"\bclaim\s+your\s+(?:prize|reward|gift\s+card|\$\d+)\b",
            r"\bunclaimed\s+(?:funds|inheritance|lottery|payout)\b",
            r"\bpay\s+(?:processing|clearance|tax|wire|release)\s+fee\s+to\s+claim\b",
            r"\bexclusive\s+reward\s+waiting\b",
            r"\byou\s+have\s+been\s+awarded\b",
        ],
        "recommendation": "Do not pay processing or clearance fees to claim unsolicited lottery or gift rewards. Legitimate prizes never require an upfront fee.",
    },
    "task_employment_fraud": {
        "title": "Task Scam & Fake Job Investment",
        "severity": "medium",
        "points": 25,
        "patterns": [
            r"\b(?:earn|make)\s+\$\d{2,4}\s+(?:per\s+day|daily|weekly|hourly)\b",
            r"\bsimple\s+tasks?\s+(?:from\s+home|online|remote)\b",
            r"\bdeposit\s+to\s+upgrade\s+(?:vip|tier|commission|level)\b",
            r"\bpart-time\s+remote\s+work.*no\s+experience\b",
            r"\blike\s+videos?\s+(?:and\s+earn|get\s+paid)\b",
            r"\brating\s+apps?\s+for\s+(?:money|commission|crypto)\b",
        ],
        "recommendation": "Legitimate employers never demand upfront cryptocurrency deposits or fee transfers to unlock salary earnings.",
    },
    "pig_butchering_investment": {
        "title": "Romance & High-Yield Crypto Investment (Pig Butchering)",
        "severity": "high",
        "points": 35,
        "patterns": [
            r"\binsider\s+(?:signal|tips?|trading\s+strategy)\b",
            r"\bhigh\s+yield\s+(?:staking|liquidity\s+pool|defi\s+node)\b",
            r"\bfinancial\s+mentor.*daily\s+profits?\b",
            r"\bprivate\s+wealth\s+(?:manager|adviser).*whatsapp\b",
            r"\bzero\s+risk.*high\s+returns?\b",
            r"\bcompound\s+interest\s+\d{2,3}%\b",
        ],
        "recommendation": "Beware of unvetted trading platforms introduced via social media or messaging apps promising risk-free high-yield returns.",
    },
    "tech_support_extortion": {
        "title": "Tech Support / Coercive Extortion Fraud",
        "severity": "high",
        "points": 35,
        "patterns": [
            r"\b(?:device|computer|windows|mac|system)\s+(?:is\s+compromised|infected|locked|disabled)\b",
            r"\bcall\s+(?:support|helpline|toll-free|agent)\s+immediately\b",
            r"\bunauthorized\s+transaction\s+detected\b",
            r"\baccount\s+will\s+be\s+(?:terminated|suspended|deleted|seized)\s+within\s+\d+\s*(?:hours|hrs|mins)\b",
            r"\bact\s+now\s+or\s+face\s+legal\s+action\b",
            r"\bi\s+have\s+recorded\s+your\s+screen\b",
            r"\bpay\s+ransom\s+in\s+bitcoin\b",
        ],
        "recommendation": "Disconnect and verify directly through official account settings. Legitimate security providers do not demand immediate gift card or crypto transfers.",
    },
    "credential_harvesting_prompt": {
        "title": "Credential Harvesting & Fake Verification",
        "severity": "high",
        "points": 30,
        "patterns": [
            r"\benter\s+(?:your\s+)?(?:password|passcode|pin|credentials)\b",
            r"\bconfirm\s+your\s+(?:identity|account|login)\s+now\b",
            r"\b2fa\s+(?:code|token|sms|verification)\s+expired\b",
            r"\bre-verify\s+your\s+(?:bank|card|account)\b",
            r"\bsecurity\s+alert.*login\s+to\s+review\b",
        ],
        "recommendation": "Never provide login credentials or 2FA codes through links received in unsolicited messages or third-party web forms.",
    },
    "urgency_social_engineering": {
        "title": "High Urgency Coercion Signals",
        "severity": "medium",
        "points": 15,
        "patterns": [
            r"\b(?:urgent|immediate\s+attention|time-sensitive)\b",
            r"\baction\s+required\s+immediately\b",
            r"\bexpires\s+in\s+\d+\s*(?:minutes|seconds|hours)\b",
            r"\bfinal\s+warning\b",
            r"\bdo\s+not\s+ignore\b",
            r"\blast\s+chance\s+to\s+claim\b",
        ],
        "recommendation": "High artificial urgency is a hallmark of social engineering intended to bypass critical thinking.",
    },
}


def detect_scam_indicators(text_corpus: str) -> Dict[str, Any]:
    """
    Scan target text (URLs, paths, queries, metadata descriptions, bio) for scam indicators.
    Returns matched categories, evidence quotes, scam score, and structured findings.
    """
    if not text_corpus:
        return {
            "matched_categories": [],
            "scam_score": 0,
            "findings": [],
        }

    clean_text = text_corpus.lower()
    matched_categories: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    total_points = 0

    for cat_id, cat_info in SCAM_CATEGORIES.items():
        matched_quotes = []
        for pattern in cat_info["patterns"]:
            matches = re.findall(pattern, clean_text, re.IGNORECASE)
            if matches:
                matched_quotes.extend(matches)

        if matched_quotes:
            unique_quotes = list(dict.fromkeys(matched_quotes))[:3]
            total_points += cat_info["points"]
            matched_categories.append({
                "category": cat_id,
                "title": cat_info["title"],
                "severity": cat_info["severity"],
                "points": cat_info["points"],
                "matches": unique_quotes,
            })

            findings.append({
                "code": f"FRAUD_SCAM_{cat_id.upper()}",
                "severity": cat_info["severity"],
                "points": cat_info["points"],
                "evidence": f"{cat_info['title']} detected. Matched triggers: {', '.join(repr(q) for q in unique_quotes)}.",
                "recommendation": cat_info["recommendation"],
            })

    capped_scam_score = min(100, total_points)
    return {
        "matched_categories": matched_categories,
        "scam_score": capped_scam_score,
        "findings": findings,
    }
