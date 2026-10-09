"""
SocialShield Fraud Engine Package (Sprint 4).
Scam indicators, Phishing detection, Impersonation signals, and Multi-factor Risk Scoring.
"""

from app.services.fraud.engine import run_fraud_assessment
from app.services.fraud.scam_detector import detect_scam_indicators
from app.services.fraud.phishing_detector import detect_phishing_signals
from app.services.fraud.impersonation_detector import detect_impersonation_signals
from app.services.fraud.risk_scorer import calculate_calibrated_risk, classify_risk_level

__all__ = [
    "run_fraud_assessment",
    "detect_scam_indicators",
    "detect_phishing_signals",
    "detect_impersonation_signals",
    "calculate_calibrated_risk",
    "classify_risk_level",
]
