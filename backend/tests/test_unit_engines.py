import pytest
from app.services.analyzer import normalize_input
from app.services.osint.username_analyzer import calculate_entropy, detect_homoglyphs
from app.services.fraud.scam_detector import detect_scam_indicators
from app.services.fraud.phishing_detector import detect_phishing_signals, levenshtein_distance
from app.services.fraud.impersonation_detector import detect_impersonation_signals
from app.services.fraud.risk_scorer import calculate_calibrated_risk, classify_risk_level
from app.services.ai_analyst.heuristic_analyst import generate_heuristic_analysis


def test_normalize_input_username():
    res = normalize_input("@john_doe")
    assert res["input_type"] == "username"
    assert res["normalized"] == "john_doe"


def test_normalize_input_url():
    res = normalize_input("https://example.com/profile")
    assert res["input_type"] == "url"
    assert res["normalized"] == "https://example.com/profile"
    assert res["host"] == "example.com"


def test_username_entropy():
    # Repetitive string has low entropy
    low_ent = calculate_entropy("aaaaaaa")
    # Varied string has higher entropy
    high_ent = calculate_entropy("aX9#mK2$")
    assert high_ent > low_ent


def test_homoglyphs_detection():
    # Cyrillic 'а' (U+0430) mimicking Latin 'a'
    homoglyphs = detect_homoglyphs("pаypal")
    assert len(homoglyphs) > 0
    assert homoglyphs[0]["mimics"] == "a"


def test_scam_detector_crypto():
    text = "Send 1 ETH to double your crypto immediately. Guaranteed 100% daily return!"
    res = detect_scam_indicators(text)
    assert res["scam_score"] > 0
    assert any(c["category"] == "crypto_giveaway" for c in res["matched_categories"])


def test_scam_detector_clean():
    text = "Welcome to the developer documentation and API reference manual."
    res = detect_scam_indicators(text)
    assert res["scam_score"] == 0
    assert len(res["matched_categories"]) == 0


def test_levenshtein_distance():
    assert levenshtein_distance("paypal", "paypal") == 0
    assert levenshtein_distance("paypal", "paypa1") == 1
    assert levenshtein_distance("apple", "bpple") == 1


def test_phishing_detector_brand_impersonation():
    res = detect_phishing_signals("http://paypal-verification-center.xyz/login")
    assert res["is_phishing_suspect"] is True
    assert res["phishing_score"] >= 35
    assert res["matched_brand"] == "paypal"


def test_impersonation_signals_vip_mimic():
    res = detect_impersonation_signals("el0nmusk_official")
    assert res["is_impersonation_suspect"] is True
    assert res["impersonation_score"] >= 30


def test_calibrated_risk_scorer():
    # High risk signals combined
    risk = calculate_calibrated_risk(
        osint_points=30,
        scam_score=50,
        phishing_score=60,
        impersonation_score=30,
        threat_feed_matched=False,
    )
    assert risk["score"] >= 65
    assert risk["level"] in ["HIGH", "CRITICAL"]

    # Clean signals
    clean_risk = calculate_calibrated_risk(0, 0, 0, 0)
    assert clean_risk["score"] == 0
    assert clean_risk["level"] == "INFO"


def test_ai_analyst_heuristic_report():
    evidence = {
        "target": "http://paypal-update.xyz",
        "input_type": "url",
        "fraud_intel": {
            "phishing_assessment": {
                "is_suspect": True,
                "score": 70,
                "matched_brand": "paypal",
            },
            "scam_assessment": {"matched_categories": []},
            "impersonation_assessment": {"is_suspect": False},
        },
    }
    report = generate_heuristic_analysis(evidence, 75, "HIGH")
    assert "executive_summary" in report
    assert "threat_actor_profile" in report
    assert len(report["mitre_attack"]) > 0
    assert report["threat_actor_profile"]["intent"] != ""
