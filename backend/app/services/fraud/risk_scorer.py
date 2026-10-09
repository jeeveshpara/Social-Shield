from typing import Any, Dict, List


def classify_risk_level(score: int) -> str:
    """Classify risk score into 5 standardized cybersecurity tiers."""
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 15:
        return "LOW"
    return "INFO"


def calculate_calibrated_risk(
    osint_points: int,
    scam_score: int,
    phishing_score: int,
    impersonation_score: int,
    threat_feed_matched: bool = False,
    is_newly_registered: bool = False,
) -> Dict[str, Any]:
    """
    Synthesize multi-dimensional threat signals into a calibrated 0-100 risk score.
    Applies compound risk multipliers and absolute threat feed overrides.
    """
    # Base weighted sum
    # OSINT weight: 20%, Phishing weight: 35%, Scam weight: 25%, Impersonation weight: 20%
    weighted_score = (
        (osint_points * 0.20) +
        (phishing_score * 0.35) +
        (scam_score * 0.25) +
        (impersonation_score * 0.20)
    )

    # Compound Threat Modifiers:
    # Multiple threat signals reinforce each other (e.g. newly registered domain + scam phrases)
    multipliers = 1.0
    active_factors = []

    if threat_feed_matched:
        active_factors.append("Active entry in global threat intelligence database (URLhaus/PhishTank)")
        weighted_score = max(weighted_score, 92.0)

    if phishing_score >= 30 and scam_score >= 25:
        multipliers += 0.25
        active_factors.append("Combined phishing lure and active fraud solicitation detected")

    if is_newly_registered and (phishing_score > 0 or scam_score > 0):
        multipliers += 0.30
        active_factors.append("Newly registered domain (<30 days old) hosting suspicious triggers")

    if impersonation_score >= 30 and (phishing_score > 0 or scam_score > 0):
        multipliers += 0.20
        active_factors.append("Impersonation of authority/brand paired with deceptive links")

    raw_final = weighted_score * multipliers
    final_score = int(round(min(100.0, max(0.0, raw_final))))
    risk_level = classify_risk_level(final_score)

    return {
        "score": final_score,
        "level": risk_level,
        "dimension_scores": {
            "osint": min(100, osint_points),
            "phishing": phishing_score,
            "scam": scam_score,
            "impersonation": impersonation_score,
        },
        "risk_factors": active_factors,
    }
