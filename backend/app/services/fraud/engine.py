from typing import Any, Dict, List, Optional
from app.services.fraud.scam_detector import detect_scam_indicators
from app.services.fraud.phishing_detector import detect_phishing_signals
from app.services.fraud.impersonation_detector import detect_impersonation_signals
from app.services.fraud.risk_scorer import calculate_calibrated_risk


def run_fraud_assessment(
    target: str,
    input_type: str,
    text_corpus: str = "",
    hostname: Optional[str] = None,
    bio_text: Optional[str] = None,
    homoglyphs: Optional[List[Dict[str, Any]]] = None,
    threat_intel_result: Optional[Dict[str, Any]] = None,
    domain_age_days: Optional[int] = None,
    osint_findings: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Unified Fraud Engine Pipeline (Sprint 4):
      - Scam Indicators: Scan for crypto doublers, task fraud, advance-fee, extortion.
      - Phishing Detection: Analyze brand lookalikes, typosquatting, deceptive subdomains, credential paths, and threat intel.
      - Impersonation Signals: Inspect username affixes, VIP targets, homoglyphs, and bio cues.
      - Multi-factor Risk Scoring: Aggregate signals with compound threat multipliers.
    """
    findings: List[Dict[str, Any]] = []

    # 1. Scam Indicators Assessment
    combined_text = f"{target} {text_corpus} {bio_text or ''}"
    scam_res = detect_scam_indicators(combined_text)
    findings.extend(scam_res.get("findings", []))

    # 2. Phishing Detection Assessment
    phishing_url = target if input_type == "url" else ""
    phishing_res = detect_phishing_signals(
        target_url=phishing_url,
        hostname=hostname,
        threat_intel_result=threat_intel_result,
    )
    findings.extend(phishing_res.get("findings", []))

    # 3. Impersonation Signals Assessment
    check_username = target if input_type == "username" else (hostname or "")
    impersonation_res = detect_impersonation_signals(
        username=check_username,
        bio_text=bio_text or text_corpus,
        homoglyphs=homoglyphs,
    )
    findings.extend(impersonation_res.get("findings", []))

    # 4. Multi-factor Calibrated Risk Scoring
    osint_base_points = sum(f.get("points", 0) for f in (osint_findings or []))
    threat_matched = bool(threat_intel_result and threat_intel_result.get("status") == "matched")
    is_newly_registered = bool(domain_age_days is not None and domain_age_days < 30)

    risk_calc = calculate_calibrated_risk(
        osint_points=osint_base_points,
        scam_score=scam_res.get("scam_score", 0),
        phishing_score=phishing_res.get("phishing_score", 0),
        impersonation_score=impersonation_res.get("impersonation_score", 0),
        threat_feed_matched=threat_matched,
        is_newly_registered=is_newly_registered,
    )

    fraud_evidence = {
        "scam_assessment": {
            "score": scam_res.get("scam_score", 0),
            "matched_categories": scam_res.get("matched_categories", []),
        },
        "phishing_assessment": {
            "score": phishing_res.get("phishing_score", 0),
            "is_suspect": phishing_res.get("is_phishing_suspect", False),
            "matched_brand": phishing_res.get("matched_brand"),
            "signals": phishing_res.get("signals", []),
        },
        "impersonation_assessment": {
            "score": impersonation_res.get("impersonation_score", 0),
            "is_suspect": impersonation_res.get("is_impersonation_suspect", False),
            "matched_target": impersonation_res.get("matched_target"),
            "signals": impersonation_res.get("signals", []),
        },
        "risk_breakdown": risk_calc,
    }

    return {
        "fraud_findings": findings,
        "fraud_evidence": fraud_evidence,
        "calibrated_risk": risk_calc,
    }
